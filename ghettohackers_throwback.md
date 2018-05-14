ghettohackers: Throwback
================

misc
------

WARNING: THIS PRODUCT CONTAINS CHEMICALS KNOWN TO THE STATE OF CALIFORNIA TO CAUSE CANCER.

We are left with only one cryptic string: 

```
Anyo!e!howouldsacrificepo!icyforexecu!!onspeedthink!securityisacomm!ditytop!urintoasy!tem!
```

It is quite obvious that letters have been replaced with exclamation marks - `n w l t i s o o s`.
We then spent the next day trying to figure out what these letters were an anagram of. Some of our best ideas:

```
solwtions
solutions (misspelled)
win to loss
is not slow
its no slow
...
```

Next, we did some recon on ghettohackers, and looked at their website on waybackmachine and stuff. Unfortunately that was all useless.

During all this, we all had a thought in our minds: what about that last `!` at the end? What is it there for?

Finally, one of us had the genius revelation that maybe the positions of the exclamation marks was relevant.

`4 ! 1 ! 18 ! 11 ! 0 ! 12 ! 15 ! 7 ! 9 ! 3`

The hint on twitter said that it was a-z with spaces. Assuming the 0 in the middle was a space, we guessed that 1 -> a, 2 -> b, etc.

[use this link because it is easy to calculate](http://rumkin.com/tools/cipher/numbers.php)

`D A R K 0 L O G I C`

Submit `dark logic` as flag for points.

Flag: `dark logic`