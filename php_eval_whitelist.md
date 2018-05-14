PHP Eval White-List
================

re/web
------

This time, we have a website that evals our stuff. At first I was pretty sad because the program blocked me from going up directories and stuff due to the basedir. After working on other problems for a bit, I came back to this one with a fresh start. Opening the source and looking at strings, I found that `shell_exec` was mentioned. I took a blind guess that this meant `shell_exec` was allowed (it probably didn't). Thus I ran `echo shell_exec("../flag");`. Somehow, it worked.

I am pretty sure this problem was misconfigured.

Flag: `OOO{Fortunately_php_has_some_rock_solid_defense_in_depth_mecanisms,_so-everything_is_fine.}`
