#!/bin/bash

efibootmgr -n $(efibootmgr | grep BitVisor | cut -c 5-8)
