project('conan-the-bot', 'c')
cc = meson.get_compiler('c')
libircclient_dep = cc.find_library('libircclient')
libtoml_dep = cc.find_library('libtoml')
executable('bot', 'main.c',
           dependencies : [libircclient_dep, libtoml_dep],
           # XXX this smells
           include_directories : include_directories('/usr/include/libircclient'))
