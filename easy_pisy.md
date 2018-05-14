Easy Pisy
================

crypto/web
------

This time, we are given a website that accepts PDF files, parses them, and signs them. However, it will only sign them if the text inside starts with `ECHO`.

Here is a screenshot of some of the source that I took while solving the problem:

![stuff](https://i.imgur.com/E5Ijunt.png)

Ignore the circled stuff, that was me trying to find a vuln. Then, I looked up [openssl_verify](http://php.net/manual/en/function.openssl-verify.php):

```
int openssl_verify ( string $data , string $signature , mixed $pub_key_id [, mixed $signature_alg = OPENSSL_ALGO_SHA1 ] )```

It seems that the default signature algorithm for this is SHA1! But SHA1 has been broken for PDFs with [SHATTERED](http://shattered.io/)

From here, it is simply a task of generating 2 pdf files with the same SHA1 hash. I used [this site](http://alf.nu/SHA1) to generate the pdfs.

[pdf1](./a.pdf)
[pdf2](./b.pdf)

I uploaded pdf1 (a.pdf) and got it signed, and then used the signature on pdf2 (b.pdf). The server recognizes this and gives the flag.

Flag: `OOO{phP_4lw4y5_d3l1v3r5_3h7_b35T_fl4g5}`