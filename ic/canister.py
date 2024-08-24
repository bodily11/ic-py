from .parser.DIDEmitter import *;
from antlr4 import *
from antlr4.InputStream import InputStream
from .candid import encode, FuncClass
from .certificate import lookup
from .principal import Principal

class Canister:
    def __init__(self, agent, canister_id, candid=None):
        self.agent = agent
        self.canister_id = canister_id
        if candid:
            self.candid = candid
        else:
            self.candid = self._fetch_candid()

    def _fetch_candid(self):
        try:
            candid = self.agent.query_raw(self.canister_id, "__get_candid_interface_tmp_hack", encode([]))
            return candid[0]['value']
        except Exception as e:
            path = [b"canister", Principal.from_str(self.canister_id).bytes, b"metadata", b"candid:service"]
            raw_cert = self.agent.read_state_raw(self.canister_id, [path])
            candid = lookup(path, raw_cert).decode()
            if candid:
                return candid
            else:
                print("Candid description not found.")
                raise ValueError(f"Canister {self.canister_id} has no candid interface available.") from e

        input_stream = InputStream(self.candid)
        lexer = DIDLexer(input_stream)
        token_stream = CommonTokenStream(lexer)
        parser = DIDParser(token_stream)
        tree = parser.program()

        emitter = DIDEmitter()
        walker =  ParseTreeWalker()
        walker.walk(emitter, tree)

        self.actor = emitter.getActor()

        for name, method in self.actor["methods"].items():
            assert type(method) == FuncClass
            anno = None if len(method.annotations) == 0 else method.annotations[0]
            setattr(self, name, CaniterMethod(agent, canister_id, name, method.argTypes, method.retTypes, anno))
            setattr(self, name + '_async', CaniterMethodAsync(agent, canister_id, name, method.argTypes, method.retTypes, anno))

class CaniterMethod:
    def __init__(self, agent, canister_id, name, args, rets, anno = None):
        self.agent = agent
        self.canister_id = canister_id
        self.name = name
        self.args = args
        self.rets = rets

        self.anno = anno

    def __call__(self, *args, **kwargs):
        if len(args) != len(self.args):
            raise ValueError("Arguments length not match")
        arguments = []
        for i, arg in enumerate(args):
            arguments.append({"type": self.args[i], "value": arg})

        effective_cansiter_id = args[0]['canister_id'] if self.canister_id == 'aaaaa-aa' and len(args) > 0 and type(args[0]) == dict and 'canister_id' in args[0] else self.canister_id
        if self.anno == 'query' or  self.anno == 'composite_query':
            res = self.agent.query_raw(
                self.canister_id,
                self.name, 
                encode(arguments),
                self.rets,
                effective_cansiter_id
                )
        else:
            res = self.agent.update_raw(
                self.canister_id,
                self.name, 
                encode(arguments),
                self.rets,
                effective_cansiter_id
            )
            
        if type(res) is not list:
            return res
        
        return list(map(lambda item: item["value"], res))

class CaniterMethodAsync:
    def __init__(self, agent, canister_id, name, args, rets, anno = None):
        self.agent = agent
        self.canister_id = canister_id
        self.name = name
        self.args = args
        self.rets = rets

        self.anno = anno

    async def __call__(self, *args, **kwargs):
        if len(args) != len(self.args):
            raise ValueError("Arguments length not match")
        arguments = []
        for i, arg in enumerate(args):
            arguments.append({"type": self.args[i], "value": arg})

        effective_cansiter_id = args[0]['canister_id'] if self.canister_id == 'aaaaa-aa' and len(args) > 0 and type(args[0]) == dict and 'canister_id' in args[0] else self.canister_id
        if self.anno == 'query' or self.anno == 'composite_query':
            res = await self.agent.query_raw_async(
                self.canister_id,
                self.name, 
                encode(arguments),
                self.rets,
                effective_cansiter_id
                )
        else:
            res = await self.agent.update_raw_async(
                self.canister_id,
                self.name, 
                encode(arguments),
                self.rets,
                effective_cansiter_id
            )
            
        if type(res) is not list:
            return res
        
        return list(map(lambda item: item["value"], res))