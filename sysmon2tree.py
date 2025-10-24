#!/usr/bin/env python3
"""Sysmon Process Tree Analyzer by deadbeesec"""
 
import os, sys, time, argparse
from typing import Dict, List, Optional
 
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
except ImportError:
    print("Please install python-evtx: pip install python-evtx")
    sys.exit(1)
 
import xml.etree.ElementTree as ET
 
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
 
class SysmonParser:
    def __init__(self):
        self.processes = {}
        self.start_time = 0
        self.total_events = 0
        self.process_events = 0
 
    def _show_progress(self, event_count):
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            speed = event_count / elapsed
            print(f"\r Processing: {event_count:,} events | Processes: {self.process_events:,} | Speed: {speed:.0f} events/sec", end="", flush=True)
 
    def parse_evtx(self, file_path, max_events=None):
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}")
            return
        
        self.start_time = time.time()
        print(f"\nParsing EVTX: {file_path}")
        print(f"Extracting Sysmon EventID=1 only")
        
        try:
            with Evtx(file_path) as log:
                event_count = 0
                skipped_count = 0
                
                for xml, record in evtx_file_xml_view(log):
                    event_count += 1
                    self.total_events = event_count
                    
                    if event_count % 1000 == 0:
                        self._show_progress(event_count)
                    
                    if max_events and event_count > max_events:
                        break
                    
                    try:
                        root = ET.fromstring(xml)
                        event_id_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
                        if event_id_elem is None:
                            event_id_elem = root.find(".//EventID")
                        
                        if event_id_elem is None or event_id_elem.text != "1":
                            skipped_count += 1
                            continue
                        
                        self._extract_process_data(root)
                        self.process_events += 1
                            
                    except ET.ParseError:
                        skipped_count += 1
                        continue
                        
        except Exception as e:
            print(f"\nError: {e}")
            return
            
        print(f"\nCompleted!")
        print(f"Total events: {self.total_events:,}")
        print(f"Process events: {self.process_events:,}")
        print(f"Time: {time.time() - self.start_time:.2f} sec")
        self._build_tree()
 
    def _extract_process_data(self, root):
        try:
            data = {}
            for elem in root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                name = elem.get("Name")
                if name and elem.text:
                    data[name] = elem.text
            
            if not data:
                for elem in root.findall(".//Data"):
                    name = elem.get("Name")
                    if name and elem.text:
                        data[name] = elem.text
            
            ts_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
            if ts_elem is None:
                ts_elem = root.find(".//TimeCreated")
            timestamp = ts_elem.get("SystemTime", "")[:19] if ts_elem is not None else ""
            
            pid = int(data.get("ProcessId", 0))
            if pid > 0:
                ppid = int(data.get("ParentProcessId", 0)) if data.get("ParentProcessId") else None
                image = data.get("Image", "Unknown")
                name = image.split("\\")[-1] if "\\" in image else image
                
                self.processes[pid] = ProcessInfo(pid, name, ppid, data.get("CommandLine", ""),
                    data.get("CurrentDirectory", ""), data.get("User", ""), timestamp)
        except:
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
<html><head><meta charset="UTF-8"><title>Sysmon Process Tree</title><style>
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
</style></head><body><div class="container">
<div class="header"><h1>🛡️ Sysmon Process Tree</h1><p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p></div>
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
function toggleProcess(header){{
var proc = header.parentElement;
var details = proc.querySelector('.details');
var children = proc.querySelector('.children');
var toggle = header.querySelector('.toggle');
if(details) details.classList.toggle('show');
if(children){{
children.classList.toggle('show');
if(toggle) toggle.textContent = children.classList.contains('show') ? '[-]' : '[+]';
}}
}}
function expandAll(){{
document.querySelectorAll('.details').forEach(d => d.classList.add('show'));
document.querySelectorAll('.children').forEach(c => c.classList.add('show'));
document.querySelectorAll('.toggle').forEach(t => {{if(t.textContent.trim()) t.textContent = '[-]';}});
}}
function collapseAll(){{
document.querySelectorAll('.details').forEach(d => d.classList.remove('show'));
document.querySelectorAll('.children').forEach(c => c.classList.remove('show'));
document.querySelectorAll('.toggle').forEach(t => {{if(t.textContent.trim()) t.textContent = '[+]';}});
}}
function searchProcess(){{
var filter = document.getElementById('searchInput').value.toLowerCase();
var allProcs = document.querySelectorAll('.process');
if(!filter){{
allProcs.forEach(p => p.style.display = '');
return;
}}
allProcs.forEach(p => p.style.display = 'none');
allProcs.forEach(proc => {{
var text = proc.textContent.toLowerCase();
if(text.includes(filter)){{
proc.style.display = '';
var elem = proc.parentElement;
while(elem){{
if(elem.classList && elem.classList.contains('process')){{
elem.style.display = '';
}}
if(elem.classList && elem.classList.contains('children')){{
elem.classList.add('show');
var parentProc = elem.parentElement;
if(parentProc && parentProc.classList.contains('process')){{
var parentHeader = parentProc.querySelector('.process-header');
if(parentHeader){{
var toggle = parentHeader.querySelector('.toggle');
if(toggle) toggle.textContent = '[-]';
}}
}}
}}
elem = elem.parentElement;
}}
}}
}});
}}
document.addEventListener('DOMContentLoaded',()=>{{
document.querySelectorAll('.tree-container>.process>.process-header').forEach(h=>{{
var parent = h.parentElement;
var children = parent.querySelector('.children');
if(children){{
children.classList.add('show');
var toggle = h.querySelector('.toggle');
if(toggle)toggle.textContent='[-]';
}}
}});
}}
document.addEventListener('DOMContentLoaded', () => {{
document.querySelectorAll('.tree-container > .process').forEach(rootProc => {{
var children = rootProc.querySelector('.children');
if(children){{
children.classList.add('show');
var header = rootProc.querySelector('.process-header');
if(header){{
var toggle = header.querySelector('.toggle');
if(toggle) toggle.textContent = '[-]';
}}
}}
}});
}});
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
        h += f'<span class="pid">PID:{proc.pid}</span><span class="ppid">| PPID:{proc.ppid or "ROOT"}</span>'
        h += f'<span class="name">| {self._esc(proc.name)}</span>'
        if has_ch: h += f'<span style="color:#6c757d">({len(proc.children)} children)</span>'
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
    parser = argparse.ArgumentParser()
    parser.add_argument("evtx_file")
    parser.add_argument("--max-events", type=int)
    parser.add_argument("--html", "-H", default="process_tree.html")
    parser.add_argument("--auto-open", action="store_true")
    args = parser.parse_args()
    
    analyzer = SysmonParser()
    analyzer.parse_evtx(args.evtx_file, args.max_events)
    analyzer.generate_html(args.html)
    
    if args.auto_open:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(args.html)}")
 
if __name__ == "__main__":
    main()
 
 
