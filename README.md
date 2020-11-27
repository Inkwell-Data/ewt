Erlang EWT Library

=
Similar to JWT but with erlang maps in Header and Claims parts instead of JSON. Keys and values
are atoms instead of binaries when it makes sense.

## Example
$ make && erl -pa ./ebin ./deps/*/ebin


    1> Key = <<"sosecret">>.
    <<"sosecret">>
    
    2> Alg = sha256.
    sha256
    
    3> Expiration = calendar:datetime_to_gregorian_seconds(calendar:universal_time()) + 24*60*60.
    63606348848
    
    4> Claims = #{user => <<"John Doe">>, roles => [manager, admin]}.
    #{roles => [manager,admin],user => <<"John Doe">>}
    
    5> Token = ewt:token(Expiration, Claims, Key, Alg).
    <<"g3QAAAACZAADYWxnZAAGc2hhMjU2ZAADdHlwZAADRVdU.g3QAAAADZAADZXhwbgUAMNw7zw5kAAVyb2xlc2wAAAACZAAHbWFuYWdlcmQABWFkbWluamQ"...>>
    
    6> ewt:claims(Token, Key).   
    {ok,#{exp => 63606348848,
          roles => [manager,admin],
          user => <<"John Doe">>}}
          
          
          
You may also use atoms auto as Alg and Expiration. In this case Expiration == universal_time() + 1 Day, Alg == sha256.

`token_dated` and `claims_dated` functions work with tokens having the fourth part - time of token creation - attached at the beginning 
of the token. Useful if you store tokens in some storage and batch delete them using something like `delete where token < ...`

## Compatibility with crypto in OTP 23 and newer
In OTP 23 and newer `crypto:hmac/3` is deprecated and replaced by `crypto:mac/4`. By default ewt tests in  the compile time
which function it should use with the help of the ?OTP_VERSION macros. If you want to test it in runtime instead define the
`?RUNTIME_OTP_VSN` macros. In both cases the wrong (too old or too new function) is never called but is still here in the module,
so it triggers deprecated function warning or removed function warning, Both these warnings are suppressed in the `-compile` attribute.

Using tokens for authorization is dangerous as the security depends on the single "secret key". Unlike salted
 hashes the token won't protect your users in case when the perpetrator got read-only access to your server. So imo
  checking if the actual token has been really issued to the user with ID encoded in the token Claims is an absolutely
  necessary step in most cases.
 