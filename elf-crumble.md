# ELF Crumble

We are provided with an ELf file with a missing section of length 807 and 8 files which sum up to length 807. We can try al permutations of these 8 files and run the ELF until we get the flag.

I generated every possible combination of ELF file with:

```python
import itertools, os
perms = [''.join(p) for p in itertools.permutations('12345678')]
dank = open("broken", "rb").read()
print len(perms)
for i in perms:
        flag = ""
        for b in i:
                cancer = open("fragment_" + str(b) + ".dat", "rb").read()
                flag += cancer
        temp = dank.replace("X"*807, flag)
        sice = open("fix" + i, "wb")
        sice.write(temp)
        sice.close()
```

I ran them until I find one that gives output with:

```python
import itertools, os, subprocess
perms = [''.join(p) for p in itertools.permutations('12345678')]
dank = open("broken", "rb").read()
print len(perms)
for i in perms:
        filename = "./fix" + i
        process = subprocess.Popen([filename], stdout=subprocess.PIPE)
        out, err = process.communicate()
        if len(out) > 0:
                print out
```

Very hacky solution because i'm lazy.

## Flag: welcOOOme
