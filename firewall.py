"""Проксі-брандмауер TCP/UDP з атомарною таблицею правил і localhost API."""
from __future__ import annotations
import argparse, ipaddress, json, os, secrets, hmac, socket, threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

def utcnow(): return datetime.now(timezone.utc).isoformat()

class JsonLogger:
    def __init__(self, path): self.path=Path(path); self.lock=threading.Lock(); self.max_bytes=2_000_000; self.backups=3
    def write(self, event, **fields):
        row={'timestamp':utcnow(),'event_type':event,**fields}
        with self.lock:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            try:
                if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                    for n in range(self.backups,0,-1):
                        old=self.path.with_name(self.path.name+f'.{n}')
                        if n==self.backups and old.exists(): old.unlink()
                        src=self.path if n==1 else self.path.with_name(self.path.name+f'.{n-1}')
                        if src.exists(): src.replace(old)
            except OSError: pass
            with self.path.open('a',encoding='utf-8') as f: f.write(json.dumps(row,ensure_ascii=False)+'\n')

@dataclass
class Rule:
    id: int=0; priority: int=100; action: str='deny'; src_ip_cidr: str='0.0.0.0/0'; dst_ip_cidr: str='0.0.0.0/0'
    src_port: int|None=None; dst_port: int|None=None; proto: str='TCP'; enabled: bool=True; description: str=''; created_at: str=''; updated_at: str=''
    def validate(self):
        if self.action not in ('allow','deny'): raise ValueError('Дія має бути allow або deny')
        if self.proto not in ('TCP','UDP'): raise ValueError('Протокол має бути TCP або UDP')
        for x in (self.src_ip_cidr,self.dst_ip_cidr):
            try: ipaddress.IPv4Network(x,strict=False)
            except Exception as e: raise ValueError(f'Некоректна IPv4 CIDR адреса: {x}') from e
        for x in (self.src_port,self.dst_port):
            if x is not None and (not isinstance(x,int) or not 1<=x<=65535): raise ValueError('Порт має бути у діапазоні 1–65535 або null')
        if not isinstance(self.priority,int): raise ValueError('Пріоритет має бути цілим числом')
    def matches(self, src, dst, sp, dp, proto):
        return self.enabled and self.proto==proto and ipaddress.IPv4Address(src) in ipaddress.IPv4Network(self.src_ip_cidr,strict=False) and ipaddress.IPv4Address(dst) in ipaddress.IPv4Network(self.dst_ip_cidr,strict=False) and (self.src_port is None or self.src_port==sp) and (self.dst_port is None or self.dst_port==dp)

class RuleManager:
    def __init__(self,path,default_action='deny',logger=None):
        if default_action not in ('allow','deny'): raise ValueError('default_action має бути allow або deny')
        self.path=Path(path); self.default_action=default_action; self.logger=logger or JsonLogger('logs/events.jsonl'); self.lock=threading.RLock(); self.rules=[]; self.next_id=1; self.load()
    def _snapshot(self): return sorted(self.rules,key=lambda r:(r.priority,r.id))
    def list(self):
        with self.lock: return [asdict(x) for x in self._snapshot()]
    def _save(self):
        data={'default_action':self.default_action,'rules':[asdict(r) for r in self._snapshot()]}; self.path.parent.mkdir(parents=True,exist_ok=True)
        tmp=self.path.with_name(self.path.name+'.tmp')
        with tmp.open('w',encoding='utf-8',newline='\n') as f: json.dump(data,f,ensure_ascii=False,indent=2); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,self.path)
    def load(self):
        try:
            data=json.loads(self.path.read_text(encoding='utf-8')); rules=[Rule(**r) for r in data.get('rules',[])]; [r.validate() for r in rules]
            with self.lock: self.rules=rules; self.default_action=data.get('default_action',self.default_action); self.next_id=max((r.id for r in rules),default=0)+1
        except FileNotFoundError: self._save()
        except Exception as e: self.logger.write('config.error',action='deny',reason=f'Помилка конфігурації: {e}') ; raise
    def add(self, values):
        with self.lock:
            d=dict(values); d.pop('id',None); d['created_at']=utcnow(); d['updated_at']=d['created_at']; r=Rule(id=self.next_id,**d); r.validate(); self.next_id+=1; self.rules.append(r); self._save()
        self.logger.write('rule.add',action=r.action,rule_id=r.id,reason=r.description); return asdict(r)
    def update(self,rid,values):
        allowed=set(Rule.__dataclass_fields__)-{'id','created_at'}
        with self.lock:
            r=next((x for x in self.rules if x.id==rid),None)
            if not r: return False
            for k,v in values.items():
                if k in allowed: setattr(r,k,v)
            r.updated_at=utcnow(); r.validate(); self._save(); snapshot=asdict(r)
        self.logger.write('rule.update',action=r.action,rule_id=rid,reason='Правило змінено'); return snapshot
    def remove(self,rid):
        with self.lock:
            old=len(self.rules); self.rules=[r for r in self.rules if r.id!=rid]
            if len(self.rules)==old: return False
            self._save()
        self.logger.write('rule.delete',action='allow',rule_id=rid,reason='Правило видалено'); return True
    def decide(self,src,dst,sp,dp,proto):
        # Copy the complete table while holding the lock; matching then sees one immutable-in-practice generation.
        with self.lock: rows=[Rule(**asdict(r)) for r in self._snapshot()]; default=self.default_action
        for r in rows:
            if r.matches(src,dst,sp,dp,proto): return r.action,r.id
        return default,0
    def conflicts(self):
        rows=[Rule(**x) for x in self.list() if x['enabled']]; out=[]
        for i,a in enumerate(rows):
            for b in rows[i+1:]:
                if a.proto!=b.proto: continue
                def overlaps_ip(x,y): return ipaddress.IPv4Network(x,strict=False).overlaps(ipaddress.IPv4Network(y,strict=False))
                def overlaps_port(x,y): return x is None or y is None or x==y
                if not(all((overlaps_ip(a.src_ip_cidr,b.src_ip_cidr),overlaps_ip(a.dst_ip_cidr,b.dst_ip_cidr),overlaps_port(a.src_port,b.src_port),overlaps_port(a.dst_port,b.dst_port)))): continue
                exact=(a.src_ip_cidr==b.src_ip_cidr and a.dst_ip_cidr==b.dst_ip_cidr and a.src_port==b.src_port and a.dst_port==b.dst_port and a.proto==b.proto)
                kind='дублікат' if exact and a.action==b.action else 'однакові умови з різними діями' if exact else 'неоднозначність пріоритету' if a.priority==b.priority else 'часткове перекриття'
                out.append({'rule_ids':[a.id,b.id],'type':kind,'explanation':f'Правила {a.id} і {b.id}: {kind}; порядок визначається пріоритетом, потім ID.','recommendation':'Залишити одне правило або уточнити IP/порти та пріоритети.'})
        # Subsumption by an earlier broader rule is a provable shadow.
        for i,b in enumerate(rows):
            for a in rows[:i]:
                def net_contains(x,y): return ipaddress.IPv4Network(y,strict=False).subnet_of(ipaddress.IPv4Network(x,strict=False))
                if a.proto==b.proto and net_contains(a.src_ip_cidr,b.src_ip_cidr) and net_contains(a.dst_ip_cidr,b.dst_ip_cidr) and (a.src_port is None or a.src_port==b.src_port) and (a.dst_port is None or a.dst_port==b.dst_port):
                    if not any(set(c['rule_ids'])=={a.id,b.id} and c['type']=='затінене правило' for c in out): out.append({'rule_ids':[a.id,b.id],'type':'затінене правило','explanation':f'Правило {b.id} повністю перекривається правилом {a.id} з вищим порядком.','recommendation':'Змінити пріоритет або звузити умови затіненого правила.'})
        for c in out: self.logger.write('conflict.detected',action='deny',rule_id=c['rule_ids'][1],reason=c['explanation'])
        return out

class ProxyService:
    def __init__(self,manager,logger): self.manager=manager; self.logger=logger; self.stop=threading.Event(); self.threads=[]; self.sockets=[]; self.client_threads=[]; self.client_lock=threading.Lock()
    def start(self,services):
        for cfg in services:
            host=cfg.get('listen_host','127.0.0.1')
            if host not in ('127.0.0.1','::1'): raise ValueError('Слухачі дозволені лише на localhost')
            target=cfg['target_host']; resolved=socket.gethostbyname(target)
            # Fixed destinations prevent client-controlled open-proxy forwarding; local-only is the safe default.
            if cfg.get('allow_external_target') is not True and not ipaddress.ip_address(resolved).is_loopback: raise ValueError('Зовнішній target потребує allow_external_target=true у конфігурації')
            fn=self._tcp if cfg['proto']=='TCP' else self._udp
            t=threading.Thread(target=fn,args=(cfg['listen_host'],cfg['listen_port'],resolved,cfg['target_port']),daemon=True); t.start(); self.threads.append(t)
    def close(self):
        self.stop.set()
        for s in self.sockets:
            try:s.close()
            except OSError:pass
        for t in self.threads:t.join(timeout=2)
        with self.client_lock: clients=list(self.client_threads)
        for t in clients:t.join(timeout=2)
    def _tcp(self,host,port,target,tp):
        srv=socket.socket(); self.sockets.append(srv); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); srv.bind((host,port)); srv.listen(); srv.settimeout(.5)
        while not self.stop.is_set():
            try:c,addr=srv.accept()
            except socket.timeout:continue
            except OSError:break
            worker=threading.Thread(target=self._tcp_client,args=(c,addr,target,tp),daemon=True)
            with self.client_lock:self.client_threads.append(worker)
            worker.start()
    def _tcp_client(self,c,addr,target,tp):
        action,rid=self.manager.decide(addr[0],target,addr[1],tp,'TCP')
        if action!='allow': self.logger.write('tcp.block',src_ip=addr[0],src_port=addr[1],dst_ip=target,dst_port=tp,protocol='TCP',action=action,rule_id=rid,reason='Політика брандмауера відхилила з’єднання',bytes=0); c.close(); return
        try:
            u=socket.create_connection((target,tp),timeout=4); c.settimeout(None); self.logger.write('tcp.connect',src_ip=addr[0],src_port=addr[1],dst_ip=target,dst_port=tp,protocol='TCP',action='allow',rule_id=rid,reason='З’єднання дозволено')
            def pipe(src,dst):
                try:
                    while True:
                        data=src.recv(65536)
                        if not data: break
                        dst.sendall(data)
                except OSError:pass
                try:dst.shutdown(socket.SHUT_WR)
                except OSError:pass
            a=threading.Thread(target=pipe,args=(c,u),daemon=True); b=threading.Thread(target=pipe,args=(u,c),daemon=True); a.start(); b.start(); a.join(); b.join()
        except OSError as e:self.logger.write('proxy.error',src_ip=addr[0],dst_ip=target,protocol='TCP',action='deny',rule_id=rid,reason=f'Помилка проксі: {e}')
        finally:c.close()
    def _udp(self,host,port,target,tp):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); self.sockets.append(s); s.bind((host,port)); s.settimeout(.5)
        while not self.stop.is_set():
            try:data,addr=s.recvfrom(65535)
            except socket.timeout:continue
            except OSError:break
            action,rid=self.manager.decide(addr[0],target,addr[1],tp,'UDP')
            fields=dict(src_ip=addr[0],src_port=addr[1],dst_ip=target,dst_port=tp,protocol='UDP',action=action,rule_id=rid,bytes=len(data))
            if action!='allow':self.logger.write('udp.block',reason='Політика брандмауера відхилила пакет',**fields); continue
            self.logger.write('udp.forward',reason='Пакет переслано',**fields)
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
                    u.settimeout(1.5); u.sendto(data,(target,tp))
                    try:resp,_=u.recvfrom(65535); s.sendto(resp,addr)
                    except socket.timeout:pass
            except OSError as e:self.logger.write('proxy.error',protocol='UDP',action='deny',rule_id=rid,reason=f'Помилка проксі: {e}')

class App:
    pass
app=None
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def reply(self,code,obj):
        body=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def read(self): return json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}')
    def authorized(self):
        supplied=self.headers.get('Authorization','')
        return hmac.compare_digest(supplied, 'Bearer '+app.api_token)
    def do_GET(self):
        if self.path=='/rules':self.reply(200,app.manager.list())
        elif self.path=='/conflicts':self.reply(200,app.manager.conflicts())
        else:self.reply(404,{'error':'Не знайдено'})
    def do_POST(self):
        if not self.authorized(): return self.reply(401,{'error':'Потрібна авторизація'})
        try:
            if self.path=='/rules':self.reply(201,app.manager.add(self.read()))
            else:self.reply(404,{'error':'Не знайдено'})
        except Exception as e:self.reply(400,{'error':str(e)})
    def do_PATCH(self):
        if not self.authorized(): return self.reply(401,{'error':'Потрібна авторизація'})
        try:
            rid=int(self.path.split('/')[-1]); result=app.manager.update(rid,self.read()); self.reply(200 if result else 404,result or {'error':'Правило не знайдено'})
        except Exception as e:self.reply(400,{'error':str(e)})
    def do_DELETE(self):
        if not self.authorized(): return self.reply(401,{'error':'Потрібна авторизація'})
        try:ok=app.manager.remove(int(self.path.split('/')[-1])); self.reply(200 if ok else 404,{'ok':ok})
        except Exception as e:self.reply(400,{'error':str(e)})

def load_config(path):
    cfg=json.loads(Path(path).read_text(encoding='utf-8')); return cfg
def main():
    p=argparse.ArgumentParser(description='Керування проксі-брандмауером'); p.add_argument('--config',default='config.json'); sub=p.add_subparsers(dest='cmd'); sub.add_parser('run'); sub.add_parser('rules'); logs=sub.add_parser('logs'); logs.add_argument('--limit',type=int,default=50); a=sub.add_parser('add'); a.add_argument('--action',choices=['allow','deny'],required=True); a.add_argument('--proto',choices=['TCP','UDP'],default='TCP'); a.add_argument('--src',default='0.0.0.0/0'); a.add_argument('--dst',default='0.0.0.0/0'); a.add_argument('--src-port',type=int); a.add_argument('--dst-port',type=int); a.add_argument('--priority',type=int,default=100); a.add_argument('--description',default='')
    d=sub.add_parser('delete'); d.add_argument('id',type=int); u=sub.add_parser('set'); u.add_argument('id',type=int); u.add_argument('--enabled',choices=['true','false']); u.add_argument('--action',choices=['allow','deny']); c=sub.add_parser('conflicts'); q=sub.add_parser('check'); q.add_argument('--src',required=True); q.add_argument('--dst',required=True); q.add_argument('--src-port',required=True,type=int); q.add_argument('--dst-port',required=True,type=int); q.add_argument('--proto',required=True,choices=['TCP','UDP'])
    args=p.parse_args(); cfg=load_config(args.config); logger=JsonLogger(cfg.get('logging',{}).get('path','logs/events.jsonl')); manager=RuleManager(cfg.get('rules_file','rules.json'),cfg.get('default_action','deny'),logger)
    if args.cmd in ('rules','logs','add','delete','set','conflicts','check'):
        if args.cmd=='rules': print(json.dumps(manager.list(),ensure_ascii=False,indent=2))
        elif args.cmd=='logs':
            if logger.path.exists():
                lines=logger.path.read_text(encoding='utf-8').splitlines(keepends=True); print(''.join(lines[-args.limit:] if args.limit>0 else []),end='')
            else: print('Журнал ще не створено')
        elif args.cmd=='add': print(json.dumps(manager.add(dict(action=args.action,proto=args.proto,src_ip_cidr=args.src,dst_ip_cidr=args.dst,src_port=args.src_port,dst_port=args.dst_port,priority=args.priority,description=args.description)),ensure_ascii=False))
        elif args.cmd=='delete': print('Видалено' if manager.remove(args.id) else 'Правило не знайдено')
        elif args.cmd=='set': print(json.dumps(manager.update(args.id,{k:v for k,v in dict(enabled=(args.enabled=='true') if args.enabled else None,action=args.action).items() if v is not None}),ensure_ascii=False))
        elif args.cmd=='conflicts': print(json.dumps(manager.conflicts(),ensure_ascii=False,indent=2))
        else: print(json.dumps(dict(zip(('action','rule_id'),manager.decide(args.src,args.dst,args.src_port,args.dst_port,args.proto))),ensure_ascii=False))
        return
    global app; app=App(); app.manager=manager; app.api_token=secrets.token_urlsafe(32); svc=ProxyService(manager,logger); app.service=svc; svc.start(cfg.get('services',[])); api=ThreadingHTTPServer(('127.0.0.1',int(cfg.get('admin',{}).get('port',8081))),Handler); print('API керування: http://127.0.0.1:'+str(api.server_port)+' (лише localhost)'); print('Тимчасовий токен API для запису правил (зберігати приватно): '+app.api_token)
    try: api.serve_forever()
    except KeyboardInterrupt: pass
    finally: api.shutdown(); api.server_close(); svc.close()
if __name__=='__main__': main()
