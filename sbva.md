# SBVA

We log into the website with the provided credentials and see it says our browser is unsupported.

We then go into burp suite and log in to see any intermediate requests it makes.

There is a 302 found page with some html and javascript in it.

We see a scoped style attribute and a `navigator.battery.charging call` in the javascript.

Apparently style scoped only works in firefox 21-54, so we bruteforce user agent strings in burp suite according to this, and using version 43.0 nets us the flag.

`flag is OOO{0ld@dm1nbr0wser1sth30nlyw@y}`
