import csv, json, threading
import socket, time
from collections import Counter
import pytest
from firewall import JsonLogger, Rule, RuleManager
import analyze_logs
from analyze_logs import filter_events, json_safe, summary
from firewall import ProxyService

@pytest.fixture
def manager(tmp_path): return RuleManager(tmp_path/'rules.json','deny',JsonLogger(tmp_path/'events.jsonl'))
def add(m,**kw):
    data=dict(action='allow',proto='TCP',src_ip_cidr='127.0.0.1/32',dst_ip_cidr='127.0.0.1/32');data.update(kw);return m.add(data)
def test_allow_deny_ports_proto_priority_default(manager):
    assert manager.decide('127.0.0.1','127.0.0.1',1000,80,'TCP')[0]=='deny'
    allow=add(manager,dst_port=80,priority=20)
    assert manager.decide('127.0.0.1','127.0.0.1',1000,80,'TCP')==('allow',allow['id'])
    assert manager.decide('127.0.0.1','127.0.0.1',1000,81,'TCP')[0]=='deny'
    deny=add(manager,action='deny',dst_port=80,priority=1)
    assert manager.decide('127.0.0.1','127.0.0.1',1000,80,'TCP')==('deny',deny['id'])
    assert manager.decide('127.0.0.1','127.0.0.1',1000,80,'UDP')[0]=='deny'
def test_validation(manager):
    with pytest.raises(ValueError): add(manager,src_ip_cidr='999.1.1.1/40')
    with pytest.raises(ValueError): add(manager,dst_port=65536)
    with pytest.raises(ValueError): add(manager,proto='ICMP')
def test_crud_persist_enable(manager):
    r=add(manager); assert manager.update(r['id'],{'enabled':False})['enabled'] is False
    assert manager.decide('127.0.0.1','127.0.0.1',1,80,'TCP')[0]=='deny'
    other=RuleManager(manager.path,'allow',manager.logger); assert other.list()[0]['id']==r['id']
    assert other.remove(r['id']) and not other.list()
def test_conflict_duplicate_and_shadow(manager):
    a=add(manager,priority=1); b=add(manager,priority=2)
    types={x['type'] for x in manager.conflicts()}; assert 'дублікат' in types and 'затінене правило' in types
def test_dynamic_threadsafe_and_logs(manager):
    errors=[]
    def writer():
        try:
            for _ in range(40): add(manager,action='deny',dst_port=443)
        except Exception as e: errors.append(e)
    t=threading.Thread(target=writer);t.start()
    while t.is_alive(): manager.list(); manager.decide('127.0.0.1','127.0.0.1',2,443,'TCP')
    t.join(); assert not errors and len(manager.list())==40
    # Перевірка рішення та додавання deny-правил не є фактами блокування трафіку.
    before=manager.logger.path.read_text(encoding='utf-8').splitlines()
    assert not any(json.loads(row)['event_type'] in {'tcp.block','udp.block'} for row in before)
    manager.logger.write('tcp.block',action='deny',src_ip='127.0.0.1',dst_port=443,protocol='TCP',rule_id=1)
    rows=[json.loads(x) for x in manager.logger.path.read_text().splitlines()]
    assert len(filter_events(rows,ip='127.0.0.1',port=443,action='deny',event_type='tcp.block'))==1
    assert summary(rows)['blocked_connections_and_packets']==1

def test_analyzer_missing_log_has_clear_message(monkeypatch,capsys,tmp_path):
    missing=tmp_path/'missing.jsonl'
    monkeypatch.setattr('sys.argv',['analyze_logs.py',str(missing)])
    with pytest.raises(SystemExit) as result:analyze_logs.main()
    assert result.value.code==2
    assert f'Журнал не знайдено: {missing}' in capsys.readouterr().err

def test_tuple_counter_json_markdown_and_csv_exports(monkeypatch,capsys,tmp_path):
    tuple_counts=Counter({('127.0.0.1','127.0.0.1',8080,'TCP'):2})
    safe=json_safe(tuple_counts)
    assert json.loads(json.dumps(safe))==[{'key':{'source_ip':'127.0.0.1','destination_ip':'127.0.0.1','destination_port':8080,'protocol':'TCP'},'count':2}]

    journal=tmp_path/'events.jsonl'
    event={'timestamp':'2026-01-01T00:00:00+00:00','event_type':'tcp.block','src_ip':'127.0.0.1','src_port':50000,'dst_ip':'127.0.0.1','dst_port':8080,'protocol':'TCP','action':'deny','rule_id':7,'reason':'Правило відхилило з’єднання','bytes':0}
    journal.write_text(''.join(json.dumps(event)+'\n' for _ in range(2)),encoding='utf-8')
    markdown=tmp_path/'reports'/'LOG_ANALYSIS_REPORT.md'; csv_path=tmp_path/'exports'/'events.csv'
    monkeypatch.setattr('sys.argv',['analyze_logs.py',str(journal),'--markdown',str(markdown),'--csv',str(csv_path)])
    analyze_logs.main()
    output=json.loads(capsys.readouterr().out)
    assert output['repeated_access_attempts'][0]['count']==2
    report=markdown.read_text(encoding='utf-8')
    assert 'Звіт аналізу журналу' in report
    assert json.loads(report.split('```json\n',1)[1].split('\n```',1)[0])==output
    with csv_path.open(encoding='utf-8-sig',newline='') as f:
        exported=list(csv.DictReader(f))
    assert len(exported)==2 and all(row['event_type']=='tcp.block' for row in exported)

def free_port(kind):
    with socket.socket(socket.AF_INET,kind) as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def test_local_tcp_proxy_observes_live_rule_changes(manager):
    manager.default_action='allow'
    target,listen=free_port(socket.SOCK_STREAM),free_port(socket.SOCK_STREAM); stop=threading.Event()
    def echo():
        s=socket.socket();s.bind(('127.0.0.1',target));s.listen();s.settimeout(.1)
        while not stop.is_set():
            try:c,_=s.accept()
            except socket.timeout:continue
            except OSError:break
            with c:
                try:c.sendall(c.recv(1024))
                except OSError:pass
        s.close()
    server=threading.Thread(target=echo,daemon=True);server.start();proxy=ProxyService(manager,manager.logger)
    proxy.start([{'proto':'TCP','listen_host':'127.0.0.1','listen_port':listen,'target_host':'127.0.0.1','target_port':target}]);time.sleep(.1)
    try:
        with socket.create_connection(('127.0.0.1',listen),timeout=2) as c:c.sendall(b'yes');assert c.recv(3)==b'yes'
        r=manager.add({'action':'deny','proto':'TCP','src_ip_cidr':'127.0.0.1/32','dst_ip_cidr':'127.0.0.1/32','dst_port':target,'priority':1})
        with socket.create_connection(('127.0.0.1',listen),timeout=2) as c:c.settimeout(1);assert c.recv(1)==b''
        assert manager.logger.path.exists()
    finally:proxy.close();stop.set();server.join(timeout=1)

def test_local_udp_proxy_observes_live_rule_changes(manager):
    manager.default_action='allow'
    target,listen=free_port(socket.SOCK_DGRAM),free_port(socket.SOCK_DGRAM);stop=threading.Event()
    def echo():
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',target));s.settimeout(.1)
        while not stop.is_set():
            try:d,a=s.recvfrom(1024);s.sendto(d,a)
            except socket.timeout:pass
            except OSError:break
        s.close()
    server=threading.Thread(target=echo,daemon=True);server.start();proxy=ProxyService(manager,manager.logger)
    proxy.start([{'proto':'UDP','listen_host':'127.0.0.1','listen_port':listen,'target_host':'127.0.0.1','target_port':target}]);time.sleep(.1)
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as c:
            c.settimeout(2);c.sendto(b'yes',('127.0.0.1',listen));assert c.recvfrom(8)[0]==b'yes'
            manager.add({'action':'deny','proto':'UDP','src_ip_cidr':'127.0.0.1/32','dst_ip_cidr':'127.0.0.1/32','dst_port':target,'priority':1})
            c.settimeout(.3);c.sendto(b'no',('127.0.0.1',listen))
            with pytest.raises(socket.timeout):c.recvfrom(8)
    finally:proxy.close();stop.set();server.join(timeout=1)
