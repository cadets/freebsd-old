#!/usr/bin/env python
from os import system

def tmux(command):
    system('tmux %s' % command)

def tmux_shell(command):
    tmux('send-keys "%s" "C-m"' % command)

# first tab - host
# second tab - start guest
tmux('select-window -t 0')
tmux_shell('cd %s' % "path to D script")
tmux('rename-window "host"')

tmux('new-window')
tmux('select-window -t 1')
tmux('%s' % "./starvm.sh")
tmux('rename-window "guest"')

