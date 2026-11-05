"""Локальний сценарій перевірки TCP/UDP та оновлення правил без перезапуску."""
import argparse, shutil, socket, tempfile, threading, time
from pathlib import Path
from firewall import JsonLogger, ProxyService, RuleManager

def free_port(kind):
    with socket.socket(socket.AF_INET,kind) as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def tcp_echo(port,stop):
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',port));s.listen();s.settimeout(.2)
    clients=[]
    while not stop.is_set():
        try:c,_=s.accept()
        except socket.timeout:continue
        except OSError:break
        def echo_client(conn):
            try:
                data=conn.recv(65535)
                if data:conn.sendall(data)
            except OSError:pass
            finally:conn.close()
        worker=threading.Thread(target=echo_client,args=(c,),daemon=True);clients.append(worker);worker.start()
    s.close()
    for worker in clients:worker.join(timeout=1)
def udp_echo(port,stop):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',port));s.settimeout(.2)
    while not stop.is_set():
        try:d,a=s.recvfrom(65535);s.sendto(d,a)
        except socket.timeout:pass
        except OSError:break
    s.close()
def check(ok,label): print(('PASS' if ok else 'FAIL')+' — '+label); return ok
def main():
    parser=argparse.ArgumentParser(description='Локальна перевірка TCP/UDP-фільтрації')
    parser.add_argument('--save-logs',action='store_true',help='Зберегти фактичні події у logs/events.jsonl')
    args=parser.parse_args()
    ok=True
    with tempfile.TemporaryDirectory() as tmp:
        log=JsonLogger(Path(tmp)/'events.jsonl');m=RuleManager(Path(tmp)/'rules.json','allow',log);stop=threading.Event()
        tcp_target,tcp_listen,udp_target,udp_listen=[free_port(socket.SOCK_STREAM),free_port(socket.SOCK_STREAM),free_port(socket.SOCK_DGRAM),free_port(socket.SOCK_DGRAM)]
        ts=[threading.Thread(target=tcp_echo,args=(tcp_target,stop),daemon=True),threading.Thread(target=udp_echo,args=(udp_target,stop),daemon=True)]
        for t in ts:t.start()
        svc=ProxyService(m,log);svc.start([{'proto':'TCP','listen_host':'127.0.0.1','listen_port':tcp_listen,'target_host':'127.0.0.1','target_port':tcp_target},{'proto':'UDP','listen_host':'127.0.0.1','listen_port':udp_listen,'target_host':'127.0.0.1','target_port':udp_target}]);time.sleep(.25)
        try:
            with socket.create_connection(('127.0.0.1',tcp_listen),timeout=2) as c:c.sendall(b'first'); tcp_ok=c.recv(16)==b'first'
            ok &= check(tcp_ok,'TCP спочатку дозволено')
            deny=m.add({'action':'deny','proto':'TCP','src_ip_cidr':'127.0.0.1/32','dst_ip_cidr':'127.0.0.1/32','dst_port':tcp_target,'priority':1,'description':'Динамічна заборона'})
            with socket.create_connection(('127.0.0.1',tcp_listen),timeout=2) as c:
                c.settimeout(.5); c.sendall(b'blocked')
                try: blocked=c.recv(16)==b''
                except ConnectionResetError: blocked=True
            ok &= check(blocked,'TCP заблоковано наступним з’єднанням після зміни правил')
            m.update(deny['id'],{'enabled':False})
            with socket.create_connection(('127.0.0.1',tcp_listen),timeout=2) as c:c.sendall(b'last');resumed=c.recv(16)==b'last'
            ok &= check(resumed,'TCP знову дозволено після вимкнення правила')
            rule=m.add({'action':'deny','proto':'UDP','src_ip_cidr':'127.0.0.1/32','dst_ip_cidr':'127.0.0.1/32','dst_port':udp_target,'priority':1})
            # Один сокет лишається відкритим для обох перевірок UDP.
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as c:
                c.settimeout(.3)
                c.sendto(b'blocked',('127.0.0.1',udp_listen))
                try:
                    c.recvfrom(10)
                    udp_block=False
                except socket.timeout:
                    udp_block=True
                ok &= check(udp_block,'UDP пакет відхилено')
                m.update(rule['id'],{'enabled':False})
                c.settimeout(2)
                c.sendto(b'ok',('127.0.0.1',udp_listen))
                udp_ok=c.recvfrom(10)[0]==b'ok'
                ok &= check(udp_ok,'UDP дозволено після вимкнення правила')
            dup=m.add({'action':'deny','proto':'TCP','src_ip_cidr':'127.0.0.1/32','dst_ip_cidr':'127.0.0.1/32','dst_port':tcp_target,'priority':2});m.add({'action':'deny','proto':'TCP','src_ip_cidr':'127.0.0.1/32','dst_ip_cidr':'127.0.0.1/32','dst_port':tcp_target,'priority':3})
            found=bool(m.conflicts());ok &= check(found,'Виявлено дубльовані/конфліктні правила')
            logrows=Path(tmp,'events.jsonl').read_text(encoding='utf-8').splitlines();ok &= check(any('tcp.block' in x for x in logrows) and any('udp.block' in x for x in logrows),'TCP і UDP блокування записані у JSONL')
        finally:
            svc.close();stop.set()
            for t in ts:t.join(timeout=2)
        if args.save_logs and log.path.exists():
            destination=Path('logs')/'events.jsonl'
            destination.parent.mkdir(parents=True,exist_ok=True)
            # Append actual events, preserving any journal already written by the service.
            with log.path.open('rb') as source, destination.open('ab') as target:
                shutil.copyfileobj(source,target)
            print(f'Журнал подій збережено: {destination}')
    raise SystemExit(0 if ok else 1)
if __name__=='__main__':main()
