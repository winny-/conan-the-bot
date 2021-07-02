project('conan-the-bot', 'c')
cc = meson.get_compiler('c')
libircclient_dep = cc.find_library('libircclient')
libtoml_dep = cc.find_library('libtoml')
libcurl_dep = dependency('libcurl')
executable('bot', 'main.c',
           dependencies : [libircclient_dep, libtoml_dep, libcurl_dep])
