You Already Know
================

Warmup
------

Unfortunately the problems were taken down immediately after the competition ended so this is off whatever screenshots I took while doing the problem.

Opening it, there's a bunch of text. We tried submitting things like OOO{it!} thinking it was wordplay, to no avail. After a few hours of frustration, I decided to open the Network tab on Google Chrome console to see what was going on behind the scenes, and amazingly, it worked:

(unfortunately, I do not have a screenshot of this. I do have the JSON response, though:

```
{"success": true, "message": "Stop overthinking it, you already know the answer here.\n\n[comment]: <> (OOO{Sometimes, the answer is just staring you in the face. We have all been there})\n\nYou already have the flag.\n\nSeriously, if you can read this, then you have the flag.\n\nSubmit it!\n"}
```

)

Flag: `OOO{Sometimes, the answer is just staring you in the face. We have all been there}`