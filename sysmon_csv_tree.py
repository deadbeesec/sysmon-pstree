#!/usr/bin/env python3
"""Sysmon CSV to Process Tree - Ultra Fast CSV Parser"""
 
import os, sys, time, argparse, csv, json
from typing import Dict, List
 
class ProcessInfo:
    def __init__(self, pid, name, ppid=None, command_line="", current_directory="", user="", timestamp=""):
        self.pid = pid
        self.name = name
        self.ppid = ppid
        self.command_line = command_line
        self.current_directory = current_directory
        self.user = user
        self.timestamp = timestamp
        self.children = []
 
class SysmonCSVParser:
    def __init__(self):
        self.processes = {}
        self.start_time = 0
        self.total_events = 0
        self.process_events = 0
 
    def parse_csv(self, file_path, max_events=None):
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}")
            return
        
        self.start_time = time.time()
        print(f"\nParsing CSV: {file_path}")
        print(f"Extracting Sysmon EventID=1 only")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    self.total_events += 1
                    
                    if self.total_events % 10000 == 0:
                        elapsed = time.time() - self.start_time
                        if elapsed > 0:
                            speed = self.total_events / elapsed
                            print(f"\rProcessing: {self.total_events:,} events | Processes: {self.process_events:,} | Speed: {speed:.0f} events/sec", end="", flush=True)
                    
                    if max_events and self.total_events > max_events:
                        break
                    
                    # Only process EventID=1 (Process Creation)
                    if row.get('EventId') != '1':
                        continue
                    
                    # Extract process info from Payload JSON
                    self._extract_process_from_row(row)
                    
        except Exception as e:
            print(f"\nError: {e}")
            import traceback
            traceback.print_exc()
            return
            
        print(f"\nCompleted!")
        print(f"Total events: {self.total_events:,}")
        print(f"Process events: {self.process_events:,}")
        elapsed = time.time() - self.start_time
        print(f"Time: {elapsed:.2f} sec")
        if elapsed > 0:
            print(f"Speed: {self.total_events / elapsed:.0f} events/sec")
        self._build_tree()
 
    def _extract_process_from_row(self, row):
        try:
            # Parse Payload JSON
            payload_str = row.get('Payload', '{}')
            payload = json.loads(payload_str)
            
            # Extract EventData
            event_data = payload.get('EventData', {}).get('Data', [])
            data = {}
            for item in event_data:
                name = item.get('@Name', '')
                text = item.get('#text', '')
                if name:
                    data[name] = text
            
            # Extract process information
            pid = int(data.get('ProcessId', 0))
            if pid <= 0:
                return
            
            ppid = int(data.get('ParentProcessId', 0)) if data.get('ParentProcessId') else None
            
            image = data.get('Image', 'Unknown')
            name = image.split('\\')[-1] if '\\' in image else image
            
            command_line = data.get('CommandLine', '')
            current_directory = data.get('CurrentDirectory', '')
            user = data.get('User', row.get('UserName', ''))
            timestamp = row.get('TimeCreated', '')[:19] if row.get('TimeCreated') else ''
            
            self.processes[pid] = ProcessInfo(
                pid=pid,
                name=name,
                ppid=ppid,
                command_line=command_line,
                current_directory=current_directory,
                user=user,
                timestamp=timestamp
            )
            self.process_events += 1
            
        except Exception as e:
            # Skip malformed rows
            pass
 
    def _build_tree(self):
        print("Building tree...")
        for pid, proc in self.processes.items():
            if proc.ppid and proc.ppid in self.processes:
                self.processes[proc.ppid].children.append(pid)
 
    def get_root_processes(self):
        roots = [p for p in self.processes.values() if p.ppid is None or p.ppid not in self.processes]
        roots.sort(key=lambda x: x.timestamp)
        return roots
 
    def generate_html(self, output_file="process_tree.html"):
        print(f"Generating HTML: {output_file}")
        roots = self.get_root_processes()
        
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Sysmon Process Tree (CSV)</title><style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:Consolas,monospace;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:20px;min-height:100vh}}
.container{{max-width:1400px;margin:0 auto;background:white;border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,0.2);overflow:hidden}}
.header{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:30px;text-align:center}}
.header h1{{font-size:32px;margin-bottom:10px}}
.stats{{display:flex;justify-content:space-around;padding:20px;background:#f8f9fa;border-bottom:2px solid #e9ecef}}
.stat-item{{text-align:center}}
.stat-item .number{{font-size:32px;font-weight:bold;color:#667eea}}
.stat-item .label{{color:#6c757d;margin-top:5px}}
.toolbar{{padding:15px 20px;background:white;border-bottom:1px solid #e9ecef;display:flex;gap:15px;align-items:center}}
.toolbar input{{flex:1;padding:12px 20px;font-size:16px;border:2px solid #e9ecef;border-radius:8px}}
.toolbar input:focus{{outline:none;border-color:#667eea}}
.btn{{padding:10px 20px;border:none;border-radius:8px;font-size:14px;font-weight:bold;cursor:pointer;transition:all 0.3s;white-space:nowrap}}
.btn-expand{{background:#28a745;color:white}}
.btn-expand:hover{{background:#218838}}
.btn-collapse{{background:#6c757d;color:white}}
.btn-collapse:hover{{background:#5a6268}}
.tree-container{{padding:30px;font-size:14px;line-height:1.6}}
.process{{margin:5px 0}}
.process-header{{padding:8px 12px;border-radius:6px;cursor:pointer;transition:background 0.2s;user-select:none}}
.process-header:hover{{background:#f8f9fa}}
.toggle{{display:inline-block;width:20px;color:#667eea;font-weight:bold}}
.pid{{color:#28a745;font-weight:bold}}
.ppid{{color:#6c757d}}
.name{{color:#007bff;font-weight:bold}}
.details{{margin-left:40px;padding:10px;background:#f8f9fa;border-left:3px solid #667eea;border-radius:4px;margin-top:5px;display:none}}
.details.show{{display:block}}
.detail-row{{margin:5px 0;word-wrap:break-word}}
.detail-label{{display:inline-block;width:60px;color:#6c757d;font-weight:bold}}
.children{{margin-left:30px;border-left:2px solid #e9ecef;padding-left:10px;display:none}}
.children.show{{display:block}}
.badge{{background:#17a2b8;color:white;padding:2px 8px;border-radius:12px;font-size:11px;margin-left:10px}}
</style></head><body><div class="container">
<div class="header"><h1>🛡️ Sysmon Process Tree</h1><p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} <span class="badge">CSV Parser</span></p></div>
<div class="stats">
<div class="stat-item"><div class="number">{len(self.processes):,}</div><div class="label">Total Processes</div></div>
<div class="stat-item"><div class="number">{len(roots):,}</div><div class="label">Root Processes</div></div>
<div class="stat-item"><div class="number">{self.total_events:,}</div><div class="label">Scanned Events</div></div>
</div>
<div class="toolbar">
<input type="text" id="searchInput" placeholder="🔍 Search process name, PID, or command line..." onkeyup="searchProcess()">
<button class="btn btn-expand" onclick="expandAll()">📂 Expand All</button>
<button class="btn btn-collapse" onclick="collapseAll()">📁 Collapse All</button>
</div>
<div class="tree-container">{self._gen_tree_html(roots)}</div>
</div><script>
function toggleProcess(e){{var d=e.nextElementSibling,c=d?d.nextElementSibling:null,t=e.querySelector('.toggle');
if(d&&d.classList.contains('details'))d.classList.toggle('show');
if(c&&c.classList.contains('children')){{c.classList.toggle('show');if(t)t.textContent=c.classList.contains('show')?'[-]':'[+]';}}}}
function expandAll(){{
document.querySelectorAll('.children').forEach(c=>c.classList.add('show'));
document.querySelectorAll('.toggle').forEach(t=>t.textContent='[-]');
}}
function collapseAll(){{
document.querySelectorAll('.children').forEach(c=>c.classList.remove('show'));
document.querySelectorAll('.toggle').forEach(t=>t.textContent='[+]');
}}
function searchProcess(){{var f=document.getElementById('searchInput').value.toLowerCase();
document.querySelectorAll('.process').forEach(p=>{{p.style.display=p.textContent.toLowerCase().includes(f)?'':'none';}});}}
document.addEventListener('DOMContentLoaded',()=>{{
document.querySelectorAll('.tree-container>.process>.process-header').forEach(h=>{{var c=h.parentElement.querySelector('.children');
if(c){{c.classList.add('show');var t=h.querySelector('.toggle');if(t)t.textContent='[-]';}}}});}});
</script></body></html>"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"Done: {output_file}")
 
    def _gen_tree_html(self, roots):
        return ''.join([self._gen_proc_html(r) for r in roots])
 
    def _gen_proc_html(self, proc):
        has_ch = len(proc.children) > 0
        tog = f'<span class="toggle">{("[+]" if has_ch else "")}</span>'
        h = f'<div class="process"><div class="process-header" onclick="toggleProcess(this)">{tog}'
        h += f'<span class="pid">PID:{proc.pid}</span> <span class="ppid">| PPID:{proc.ppid or "ROOT"}</span> '
        h += f'<span class="name">| {self._esc(proc.name)}</span>'
        if has_ch: h += f' <span style="color:#6c757d">({len(proc.children)} children)</span>'
        h += '</div><div class="details">'
        if proc.command_line: h += f'<div class="detail-row"><span class="detail-label">CMD:</span>{self._esc(proc.command_line)}</div>'
        if proc.current_directory: h += f'<div class="detail-row"><span class="detail-label">DIR:</span>{self._esc(proc.current_directory)}</div>'
        if proc.user: h += f'<div class="detail-row"><span class="detail-label">USER:</span>{self._esc(proc.user)}</div>'
        if proc.timestamp: h += f'<div class="detail-row"><span class="detail-label">TIME:</span>{proc.timestamp}</div>'
        h += '</div>'
        if has_ch:
            h += '<div class="children">'
            children = [self.processes[c] for c in proc.children if c in self.processes]
            children.sort(key=lambda x: x.timestamp)
            for child in children:
                h += self._gen_proc_html(child)
            h += '</div>'
        h += '</div>'
        return h
 
    def _esc(self, t):
        if not t: return ""
        return t.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')
 
def main():
    parser = argparse.ArgumentParser(description="Sysmon CSV to Process Tree - Ultra Fast")
    parser.add_argument("csv_file", help="Path to EvtxECmd CSV output file")
    parser.add_argument("--max-events", type=int, help="Limit processing to first N events")
    parser.add_argument("--html", "-H", default="process_tree.html", help="Output HTML file path")
    parser.add_argument("--auto-open", action="store_true", help="Automatically open HTML in browser")
    args = parser.parse_args()
    
    analyzer = SysmonCSVParser()
    analyzer.parse_csv(args.csv_file, args.max_events)
    analyzer.generate_html(args.html)
    
    if args.auto_open:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(args.html)}")
 
if __name__ == "__main__":
    main()