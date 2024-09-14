import argparse
import os
_HANDLER_FUNC = 'handle'
def set_handle_func(name):
    global _HANDLER_FUNC
    _HANDLER_FUNC = name

_MANAGER_ATTR = '__MANAGER'
def set_manager_attr(name):
    global _MANAGER_ATTR
    _MANAGER_ATTR = name

class CommandError(Exception):
    pass

def trap_parser_error(message):
    raise CommandError(message)

class ArgSet:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

class Command:
    def __init__(self, name, args, parser=None, handler=None):
        self.name = name
        self.args = args
        self.parser = parser
        self.handler = handler

    def set_parser(self, parser):
        self.parser = parser

    def set_handler(self, handler):
        self.handler = handler

    def get_parser(self):
        if not isinstance(self.parser, argparse.ArgumentParser):
            raise CommandError(f'Parser for {self} is not available')
        return self.parser

    def get_handler(self):
        if self.handler is None:
            raise CommandError(f'Handler for {self} is not available')
        return self.handler

    def execute(self):
        handler = self.get_handler()
        if callable(handler):
            return handler(self)
        handle_func = getattr(handler, _HANDLER_FUNC)
        if not callable(handle_func):
            handle_func = getattr(handler, handle_func)
        return handle_func(self)

class CommandsManager:
    def __init__(self):
        self.registry = {}
        self.handlers = {}

    def update(self, name, *args, **kwargs):
        self.get(name).add_argument(*args, **kwargs)

    def contains(self, name):
        return name in self.registry

    def get(self, name):
        return self.registry.get(name, None)

    def register(self, name, *init_args, desc=None, handler=None, parser=None):
        if self.contains(name):
            raise CommandError(f'Command conflicts with {self.get(name)}')
        if parser is None:
            parser = argparse.ArgumentParser(name, description=desc)
        setattr(parser, _MANAGER_ATTR, self)
        parser.error = trap_parser_error
        self.registry[name] = parser
        if init_args:
            for arg in init_args:
                self.update(name, *arg.args, **arg.kwargs)
        if handler is not None:
            self.register_handler(name, handler)
    
    def check_command_available(self, name):
        if not self.contains(name):
            raise CommandError(f'command not found: {name}')

    def parse(self, command):
        args = command.strip().split()
        if not args:
            raise CommandError(f'No command is found; The input ({command}) seems to be empty')
        self.check_command_available(args[0])
        parser = self.get(args[0])
        return Command(args[0], parser.parse_args(args[1:]), parser)

    def register_handler(self, name, func):
        self.check_command_available(name)
        self.handlers[name] = func

    def get_executable(self, command):
        command = self.parse(command)
        if not command.name in self.handlers:
            raise CommandError(f'Command {command.name} has no handler')
        command.set_handler(self.handlers.get(command.name))
        return command

    def execute(self, command):
        return self.get_executable(command).execute()

    def help_message(self, command=None):
        if command is None:
            msg = []
            for name in self.registry:
                msg.append(self.get(name).format_usage())
            return os.linesep.join(msg)
        return self.get(command).format_help()
