"""Пошук подій JSONL та експорт знеособлених звітів."""
import argparse,csv,json,sys
from collections import Counter
from pathlib import Path

def read_events(path):
    rows=[]
    with open(path,encoding='utf-8') as f:
        for n,line in enumerate(f,1):
            try: rows.append(json.loads(line))
            except json.JSONDecodeError: print(f'Пропущено пошкоджений рядок {n}')
    return rows
def filter_events(rows,ip=None,port=None,proto=None,start=None,end=None,event_type=None,action=None,rule_id=None):
    def keep(e):
        ips=(e.get('src_ip'),e.get('dst_ip')); ports=(e.get('src_port'),e.get('dst_port'))
        if ip and ip not in ips:return False
        if port and port not in ports:return False
        if proto and e.get('protocol','').upper()!=proto.upper():return False
        if event_type and e.get('event_type')!=event_type:return False
        if action and e.get('action')!=action:return False
        if rule_id is not None and e.get('rule_id')!=rule_id:return False
        ts=e.get('timestamp','')
        if start and ts<start:return False
        if end and ts>end:return False
        return True
    return [x for x in rows if keep(x)]
def summary(rows):
    # Правило deny в події керування (наприклад, rule.add) описує конфігурацію,
    # а не заблокований пакет. Блоками є лише події, створені мережею-проксі.
    traffic_events={'tcp.block','udp.block','tcp.connect','udp.forward'}
    blocked=[e for e in rows if e.get('event_type') in {'tcp.block','udp.block'} and e.get('action')=='deny']
    counts=Counter(e.get('rule_id') for e in rows if e.get('event_type') in traffic_events and e.get('rule_id'))
    return {'total_events':len(rows),'blocked_connections_and_packets':len(blocked),'top_blocked_ips':Counter(e.get('src_ip','?') for e in blocked).most_common(10),'top_blocked_ports':Counter(e.get('dst_port','?') for e in blocked).most_common(10),'rule_hits':counts.most_common(),'repeated_access_attempts':Counter((e.get('src_ip'),e.get('dst_ip'),e.get('dst_port'),e.get('protocol')) for e in blocked)}

def json_safe(value):
    """Recursively convert summary values to JSON-compatible values."""
    if isinstance(value,Counter):
        if all(isinstance(key,(str,int,float,bool)) or key is None for key in value):
            return {str(key) if key is None else key:json_safe(count) for key,count in value.items()}
        entries=[]
        for key,count in value.most_common():
            if isinstance(key,tuple) and len(key)==4:
                key_value={'source_ip':key[0],'destination_ip':key[1],'destination_port':key[2],'protocol':key[3]}
            else:
                key_value=json_safe(key)
            entries.append({'key':key_value,'count':count})
        return entries
    if isinstance(value,dict):
        if all(isinstance(key,(str,int,float,bool)) or key is None for key in value):
            return {str(key) if key is None else key:json_safe(item) for key,item in value.items()}
        return [{'key':json_safe(key),'value':json_safe(item)} for key,item in value.items()]
    if isinstance(value,(list,tuple)):
        return [json_safe(item) for item in value]
    return value

def main():
    p=argparse.ArgumentParser(description='Пошук та аналіз журналу JSONL'); p.add_argument('path',nargs='?',default='logs/events.jsonl'); p.add_argument('--ip');p.add_argument('--port',type=int);p.add_argument('--protocol',choices=['TCP','UDP']);p.add_argument('--start');p.add_argument('--end');p.add_argument('--event-type');p.add_argument('--action',choices=['allow','deny']);p.add_argument('--rule-id',type=int);p.add_argument('--markdown');p.add_argument('--csv');a=p.parse_args()
    try: events=read_events(a.path)
    except FileNotFoundError:
        print(f'Журнал не знайдено: {a.path}. Запустіть `python dynamic_demo.py --save-logs` або вкажіть шлях до наявного JSONL-файлу.',file=sys.stderr)
        raise SystemExit(2)
    rows=filter_events(events,a.ip,a.port,a.protocol,a.start,a.end,a.event_type,a.action,a.rule_id); s=summary(rows); report=json_safe(s); rendered=json.dumps(report,ensure_ascii=False,indent=2)
    print(rendered)
    if a.csv:
        csv_path=Path(a.csv)
        csv_path.parent.mkdir(parents=True,exist_ok=True)
        with csv_path.open('w',newline='',encoding='utf-8-sig') as f:
            w=csv.DictWriter(f,fieldnames=sorted(set().union(*(x.keys() for x in rows))) if rows else ['timestamp','event_type']);w.writeheader();w.writerows(rows)
    if a.markdown:
        output=Path(a.markdown)
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text('# Звіт аналізу журналу\n\nПідсумок сформовано з подій відфільтрованого JSONL-журналу.\n\n```json\n'+rendered+'\n```\n',encoding='utf-8')
if __name__=='__main__':main()
