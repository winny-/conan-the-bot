project('conan-the-bot', 'c')
cc = meson.get_compiler('c')
libircclient_dep = cc.find_library('libircclient')
executable('bot', 'main.c',
           dependencies : libircclient_dep,
           # XXX this smells
           include_directories : include_directories('/usr/include/libircclient'))
