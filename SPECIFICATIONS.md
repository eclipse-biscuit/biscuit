# Biscuit, a bearer token with offline attenuation and decentralized verification

## Introduction

Biscuit is a bearer token that supports offline attenuation, can be verified
by any system that knows the root public key, and provides a flexible
authorization language based on logic programming. It is serialized as
Protocol Buffers [^protobuf], and designed to be small enough for storage in
HTTP cookies.

### Vocabulary

- Datalog: a declarative logic language that works on facts defining data relationship,
  rules creating more facts if conditions are met, and queries to test such conditions
- check: a restriction on the kind of operation that can be performed with
  the token that contains it, represented as a datalog query in biscuit. For the operation
  to be valid, all of the checks defined in the token and the authorizer must succeed
- allow/deny policies: a list of datalog queries that are tested in a sequence
  until one of them matches. They can only be defined in the authorizer
- block: a list of datalog facts, rules and checks. The first block is the authority
  block, used to define the basic rights of a token
- (Verified) Biscuit: a completely parsed biscuit, whose signatures and final proof
  have been successfully verified
- Unverified Biscuit: a completely parsed biscuit, whose signatures and final proof
  have not been verified yet. Manipulating unverified biscuits can be useful for generic
  tooling (eg inspecting a biscuit without knowing its public key)
- Authorized Biscuit: a completely parsed biscuit, whose signatures and final proof
  have been successfully verified and that was authorized in a given context, by running
  checks and policies.  
  An authorized biscuit may carry informations about the successful authorization such as
  the allow query that matched and the facts generated in the process
- Authorizer: the context in which a biscuit is evaluated. An authorizer may carry facts,
  rules, checks and policies.

### Overview

A Biscuit token is defined as a series of blocks. The first one, named "authority block",
contains rights given to the token holder. The following blocks contain checks that
reduce the token's scope, in the form of logic queries that must succeed.
The holder of a biscuit token can at any time create a new token by adding a
block with more checks, thus restricting the rights of the new token, but they
cannot remove existing blocks without invalidating the signature.

The token is protected by public key cryptography operations: the initial creator
of a token holds a secret key, and any verifier for the token needs only to know
the corresponding public key.
Any attenuation operation will employ ephemeral key pairs that are meant to be
destroyed as soon as they are used.

There is also a sealed version of that token that prevents further attenuation.

The logic language used to design rights, checks, and operation data is a
variant of datalog that accepts expressions on some data types.

## Semantics

A biscuit is structured as an append-only list of blocks, containing _checks_,
and describing authorization properties. As with Macaroons[^macaroons],
an operation must comply with all checks in order to be allowed by the biscuit.

Checks are written as queries defined in a flavor of Datalog that supports
expressions on some data types[^datalog], without support for negation. This
simplifies its implementation and makes the check more precise.

### Logic language

#### Terminology

A Biscuit Datalog program contains _facts_ and _rules_, which are made of
_predicates_ over the following types:

- _variable_
- _integer_
- _string_
- _byte array_
- _date_
- _boolean_
- _null_
- _set_ a deduplicated list of values of any type, except _variable_ or _set_
- _array_ an array of values of any type, expect  _variable_ (nested arrays are allowed)
- _map_ a map of key/value pairs. keys must be either strings or integers, values can be of any type, except _variable_ (nested maps are allowed)

While a Biscuit token does not use a textual representation for storage, we
use one for parsing and pretty printing of Datalog elements.

A _predicate_ has the form `Predicate(v0, v1, ..., vn)`.

A _fact_ is a _predicate_ that does not contain any _variable_.

A _rule_ has the form:
`Pr(r0, r1, ..., rk) <- P0(t0_1, t0_2, ..., t0_m1), ..., Pn(tn_1, tn_2, ..., tn_mn), E0(v0, ..., vi), ..., Ex(vx, ..., vy)`.
The part of the left of the arrow is called the _head_ and on the right, the
_body_. In a _rule_, each of the `ri` or `ti_j` terms can be of any type. A
_rule_ is safe if all of the variables in the head appear somewhere in the body.
We also define an _expression_ `Ex` over the variables `v0` to `vi`. _Expressions_
define a test of variable values when applying the _rule_. If the _expression_
returns `false`, the _rule_ application fails.

A _query_ is a type of _rule_ that has no head. It has the following form:
`?- P0(t1_1, t1_2, ..., t1_m1), ..., Pn(tn_1, tn_2, ..., tn_mn), C0(v0), ..., Cx(vx)`.
When applying a _rule_, if there is a combination of _facts_ that matches the
body's predicates, we generate a new _fact_ corresponding to the head (with the
variables bound to the corresponding values).

A _check_ is a list of _query_ for which the token validation will fail if it cannot
produce any fact. A single query needs to match for the fact to succeed.
If any of the cheks fails, the entire verification fails.

An _allow policy_ or _deny policy_ is a list of _query_. If any of the queries produces something,
the policy matches, and we stop there, otherwise we test the next one. If an
_allow policy_ succeeds, the token verification succeeds, while if a _deny policy_
succeeds, the token verification fails. Those policies are tested after all of
the _checks_ have passed.

We will represent the various types as follows:

- variable: `$variable` (the variable name is converted to an integer id through the symbol table)
- integer: `12`
- string: `"hello"` (strings are converted to integer ids through the symbol table)
- byte array: `hex:01A2`
- date in RFC 3339 format: `1985-04-12T23:20:50.52Z`
- boolean: `true` or `false`
- null: `null`, supported since block version 6
- set: `{ "a", "b", "c"}`
- array: `[ "a", true, null]`, supported since block version 6
- map: `{ "a": true, 12: "a" }`, supported since block version 6

As an example, assuming we have the following facts: `parent("a", "b")`,
`parent("b", "c")`, `parent("c", "d")`. If we apply the rule
`grandparent($x, $z) <- parent($x, $y), parent($y, $z)`, we will try to replace
the predicates in the body by matching facts. We will get the following
combinations:

- `grandparent("a", "c") <- parent("a", "b"), parent("b", "c")`
- `grandparent("b", "d") <- parent("b", "c"), parent("c", "d")`

The system will now contain the two new facts `grandparent("a", "c")` and
`grandparent("b", "d")`. Whenever we generate new facts, we have to reapply all of
the system's rules on the facts, because some rules might give a new result. Once
rules application does not generate any new facts, we can stop.

#### Data types

An _integer_ is a signed 64 bits integer. It supports the following operations:
lower than, greater than, lower than or equal, greater than or equal, strict equal,
strict not equal, set inclusion, addition, subtraction, mutiplication, division,
bitwise and, bitwise or, bitwise xor, lenient equal, lenient not equal, typeof.

A _string_ is a suite of UTF-8 characters. It supports the following
operations: prefix, suffix, strict equal, strict not equal, set inclusion, regular
expression, concatenation (with `+`), substring test (with `.contains()`), lenient equal, lenient not equal, typeof.

A _byte array_ is a suite of bytes. It supports the following
operations: strict equal, strict not equal, set inclusion, lenient equal, lenient not equal, typeof.

A _date_ is a 64 bit unsigned integer representing a UTC unix timestamp (number of seconds since 1970-01-01T00:00:00Z). It supports
the following operations: `<`, `<=` (before), `>`, `>=` (after), strict equal,
strict not equal, set inclusion, lenient equal, lenient not equal, typeof.

A _boolean_ is `true` or `false`. It supports the following operations:
`===` (strict equal), `!==` (strict not equal), eager or, eager and, set inclusion, `==` (lenient equal), `!=` (lenient not equal), typeof, short-circuiting or, short-circuiting and.

A _null_ is a default type indicating the absence of value. It supports `===` (strict equal), `!==` (strict not equal), `==` (lenient equal) and `!=` (lenient not equal), typeof. `null` is always equal to itself.

A _set_ is a deduplicated list of terms of the same type. It cannot contain
variables or other sets. It supports strict equal, strict not equal, intersection, union,
set inclusion, lenient equal, lenient not equal, any, all, typeof.

An _array_ is an ordered list of terms, not necessarily of the same type. It supports `===` (strict equal), `!==` (strict not equal), `==` (lenient equal) and `!=` (lenient not equal), contains, prefix, suffix, get, typeof.

A _map_ is an unordered collection of key/value pairs, with unique keys. Keys are either strings or integers, values can be any term. It supports `===` (strict equal), `!==` (strict not equal), `==` (lenient equal) and `!=` (lenient not equal), contains, get, typeof.

#### Grammar

The logic language is described by the following EBNF grammar:

```
<origin_clause> ::= <sp>? "trusting " <origin_element> <sp>? ("," <sp>? <origin_element> <sp>?)*
<origin_element> ::= "authority" | "previous" | <signature_alg>  "/" <bytes>
<signature_alg> ::= "ed25519"

<block> ::= (<origin_clause> ";" <sp>?)? (<block_element> | <comment> )*
<block_element> ::= <sp>? ( <check> | <fact> | <rule> ) <sp>? ";" <sp>?
<authorizer> ::= (<authorizer_element> | <comment> )*
<authorizer_element> ::= <sp>? ( <policy> | <check> | <fact> | <rule> ) <sp>? ";" <sp>?

<comment> ::= "//" ([a-z] | [A-Z] ) ([a-z] | [A-Z] | [0-9] | "_" | ":" | " " | "\t" | "(" | ")" | "$" | "[" | "]" )* "\n"

<fact> ::= <name> "(" <sp>? <fact_term> (<sp>? "," <sp>? <fact_term> )* <sp>? ")"
<rule> ::= <predicate> <sp>? "<-" <sp>? <rule_body>
<check> ::= "check" <sp> ( "if" | "all" ) <sp> <rule_body> (<sp>? " or " <sp>? <rule_body>)* <sp>?
<policy> ::= ("allow" | "deny") <sp> "if" <sp> <rule_body> (<sp>? " or " <sp>? <rule_body>)* <sp>?

<rule_body> ::= <rule_body_element> <sp>? ("," <sp>? <rule_body_element> <sp>?)* (<sp> <origin_clause>)?
<rule_body_element> ::= <predicate> | <expression>

<predicate> ::= <name> "(" <sp>? <term> (<sp>? "," <sp>? <term> )* <sp>? ")"
<term> ::= <fact_term> | <variable>
<fact_term> ::= <boolean> | <string> | <number> | ("hex:" <bytes>) | <date> | <null> | <set>
<set_term> ::= <boolean> | <string> | <number> | <bytes> | <date> | <null>


<number> ::= "-"? [0-9]+
<bytes> ::= ([a-z] | [0-9])+
<boolean> ::= "true" | "false"
<null> ::= "null"
<date> ::= [0-9]* "-" [0-9] [0-9] "-" [0-9] [0-9] "T" [0-9] [0-9] ":" [0-9] [0-9] ":" [0-9] [0-9] ( "Z" | ( ("+" | "-") [0-9] [0-9] ":" [0-9] [0-9] ))
<set> ::= "{" <sp>? ( <set_term> ( <sp>? "," <sp>? <set_term>)* <sp>? )? "}"
<array> ::= "[" <sp>? ( <term> ( <sp>? "," <sp>? <term>)* <sp>? )? "]"
<map_entry> ::= (<string> | <number>) <sp>? ":" <sp>? <term>
<map> ::= "{" <sp>? ( <map_entry> ( <sp>? "," <sp>? <map_entry>)* <sp>? )? "}"

<expression> ::= <expression_element> (<sp>? <operator> <sp>? <expression_element>)*
<expression_element> ::= <expression_unary> | (<expression_term> <expression_method>? )
<expression_unary> ::= "!" <sp>? <expression>
<expression_method> ::= "." <method_name> "(" <sp>? (<term> ( <sp>? "," <sp>? <term>)* )? <sp>? ")"
<method_name> ::= (extern::)?([a-z] | [A-Z] ) ([a-z] | [A-Z] | [0-9] | "_" )*

<expression_term> ::= <term> | ("(" <sp>? <expression> <sp>? ")")
<operator> ::= "<" | ">" | "<=" | ">=" | "===" | "!==" | "&&" | "||" | "+" | "-" | "*" | "/" | "&" | "|" | "^" | "==" | "!=="

<sp> ::= (" " | "\t" | "\n")+
```

The `name`, `variable` and `string` rules are defined as:

- `name`:
  - first character is any UTF-8 letter character
  - following characters are any UTF-8 letter character, numbers, `_` or `:`
- `variable`:
  - first character is `$`
  - following characters are any UTF-8 letter character, numbers, `_` or `:`
- `string`:
  - first character is `"`
  - any printable UTF-8 character except `"` which must be escaped as `\"`
  - last character is `"`

The order of operations in expressions is the following:

- parentheses;
- methods;
- `*` `/` (left associative)
- `+` `-` (left associative)
- `&` (left associative)
- `|` (left associative)
- `^` (left associative)
- `<=` `>=` `<` `>` `==` (**not** associative: they have to be combined with parentheses)
- `&&` (left associative)
- `||` (left associative)

### Scopes

Since the first block defines the token's rights through facts and rules, and
later blocks can define their own facts and rules, we must ensure the token
cannot increase its rights with later blocks.

This is done through execution scopes: by default, a block's rules and checks can only
apply on facts created in the authority, in the current block or in the authorizer.
Rules, checks and policies defined in the authorizer can only apply on facts created
in the authority or in the authorizer.

Example:

- the token contains `right("file1", "read")` in the first block
- the token holder adds a block with the fact `right("file2", "read")`
- the verifier adds:
  - `resource("file2")`
  - `operation("read")`
  - `check if resource($res), operation($op), right($res, $op)`

The verifier's check will fail because when it is evaluated, it only sees
`right("file1", "read")` from the authority block.

#### Scope annotations

Rules (and blocks) can specify _trusted origins_ through a special `trusting` annotation. By default,
only the current block, the authority block and the verifier are trusted. This default can be overriden:

 - at the block level
 - at the rule level (which takes precedence over block-level annotations)

The scope annotation can be a combination of either:

 - `authority` (default behaviour): the authorizer, the current block
    and the authority one are trusted;
 - `previous` (only available in blocks): the authorizer, the current block and the previous
   blocks (including the authority) are trusted;
 - a public key: the authorizer, the current block and the blocks
   carrying an external signature verified by the provided public key
   are trusted.

`previous` is only available in blocks, and is ignored when used in the authorizer.

When there are multiple scope annotations, the trusted origins are _added_. Note that the current block and the authorizer
are _always_ trusted.

This scope annotation is then turned into a set of block ids before evaluation. Authorizer facts and rules are assigned a dedicated
block id that's distinct from the authority and from the extra blocks.

Only facts which origin is a _subset_ of these trusted origins are matched. The authorizer block id and the current block id are always
part of these trusted origins.

### Checks

Checks are logic queries evaluating conditions on facts.
To validate an operation, all of a token's checks must succeed.

One block can contain one or more checks.

Their text representation is `check if`, `check all` or `reject if` followed by the body of the query.
There can be multiple queries inside of a check, it will succeed if any of them
succeeds (in the case of `reject if`, the check will fail if any query matches). They are separated by a `or` token.

- a `check if` query succeeds if it finds one set of facts that matches the body and expressions
- a `check all` query succeeds if all the sets of facts that match the body also succeed the expression.
- a `reject if` query succeeds if no set of facts matches the body and expressions

`check all` can only be used starting from block version 4.  
`reject if` can only be used starting from block version 6.

Here are some examples of writing checks:

#### Basic token

This first token defines a list of authority facts giving `read` and `write`
rights on `file1`, `read` on `file2`. The first check ensures that the operation
is `read` (and will not allow any other `operation` fact), and then that we have
the `read` right over the resource.  
The second check ensures that the resource is either `file1` or `file2`.  
The third check ensures that the resource is not `file1`.

```
authority:
  right("file1", "read");
  right("file2", "read");
  right("file1", "write");
----------
Block 1:
check if
  resource($0),
  operation("read"),
  right($0, "read")  // restrict to read operations
----------
Block 2:
check if
  resource("file1")  
  or resource("file2") // restrict to file1 or file2
----------
Block 3:
reject if
  resource("file1")  // forbid using the token on file1
```

The verifier side provides the `resource` and `operation` facts with information
from the request.

If the verifier provided the facts `resource("file1")` and
`operation("read")`, the rule application of the first check would see
`resource("file1"), operation("read"), right("file1", "read")`
with `X = "file1"`, so it would succeed, the second check would also succeed because it expects `resource("file1")` or `resource("file2")`. The third check would then fail because it would match on `resource("file1")`.

If the verifier provided the facts `resource("file2")` and
`operation("read")`, all checks would succeed.

#### Broad authority rules

In this example, we have a token with very large rights, that will be attenuated
before giving to a user. The authority block can define rules that will generate
facts depending on data provided by the verifier. This helps reduce the size of
the token.

```
authority:

// if there is an ambient resource and we own it, we can read it
right($0, "read") <- resource($0), owner($1, $0);
// if there is an ambient resource and we own it, we can write to it
right($0, "write") <- resource($0), owner($1, $0);
----------
Block 1:

check if
  right($0, $1),
  resource($0),
  operation($1)
----------
Block 2:

check if
  resource($0),
  owner("alice", $0) // defines a token only usable by alice
```

These rules will define authority facts depending on verifier data.
If we had the facts `resource("file1")` and
`owner("alice", "file1")`, the authority rules will define
`right("file1", "read")` and `right("file1", "write")`,
which will allow check 1 and check 2 to succeed.

If the owner ambient fact does not match the restriction in the second check, the
token verification will fail.

### Allow/deny policies

Allow and deny policies are queries that are tested one by one, after all of the
checks have succeeded. If one of them succeeds, we stop there, otherwise we test
the next one. If an allow policy succeeds, token verification succeeds, while if
a deny policy succeeds, the token verification fails. If none of these policies
are present, the verification will fail.

They are written as `allow if` or `deny if` followed by the body of the query.
Same as for checks, the body of a policy can contain multiple queries, separated
by "or". A single query needs to match for the policy to match.

### Expressions

We can define queries or rules with expressions on some predicate values, and
restrict usage based on ambient values:

```
authority:

right("/folder/file1", "read");
right("/folder/file2", "read");
right("/folder2/file3", "read");
----------
check if resource($0), right($0, $1)
----------
check if time($0), $0 < 2019-02-05T23:00:00Z // expiration date
----------
check if source_IP($0), ["1.2.3.4", "5.6.7.8"].contains($0) // set membership
----------
check if resource($0), $0.starts_with("/folder/") // prefix operation on strings
```

Executing an expression must always return a boolean, and all variables
appearing in an expression must also appear in other predicates of the
rule.

#### Execution

Expressions are internally represented as a series of opcodes for a stack based
virtual machine. There are four kinds of opcodes:

- _value_: a raw value of any type. If it is a variable, the variable must also
  appear in a predicate, so the variable gets a real value for execution. When
  encountering a _value_ opcode, we push it onto the stack
- _unary operation_: an operation that applies on one argument. When executed,
  it pops a value from the stack, applies the operation, then pushes the result
- _binary operation_: an operation that applies on two arguments. When executed,
  it pops two values from the stack, applies the operation, then pushes the result
- _closure_: a function definition containing the name of parameters and the body of the function expressed as a list of opcodes. Closures can be nested.

After executing, the stack must contain only one value, of the boolean type.

##### Closures

Closures are evaluated recursively. When executing a closure, a new empty stack is created, and the closure opcodes are evaluated. After evaluation, the stack must contain only one value, of any type, which is then pushed on the parent stack.

The closure arguments are treated the same way as datalog variables and are replaced by their value when the corresponding opcode is evaluated.

Shadowing (defining a parameter with the same name as a variable already in scope) is not allowed and should be rejected before starting the evaluation.

Short-circuiting boolean operators (`&&` and `||`) are implemented using closures: the right-hand side is defined in a closure (taking zero arguments) and is only evaluated as needed.

##### Operations

Here are the currently defined unary operations:

- _negate_: boolean negation
- _parens_: returns its argument without modification (this is used when printing
  the expression, to avoid precedence errors)
- _length_: defined on strings, byte arrays and sets (for strings, _length_ is defined as the number of bytes in the UTF-8 encoded string; the alternative of counting grapheme clusters would be inconsistent between languages)
- _type_, defined on all types, returns a string (v6 only)
  - `integer`
  - `string`
  - `date`
  - `bytes`
  - `bool`
  - `set`
  - `null`
- *external* call: implementation-defined, allows the datalog engine to call out to a function provided by the host language

Here are the currently defined binary operations:

- _less than_, defined on integers and dates, returns a boolean
- _greater than_, defined on integers and dates, returns a boolean
- _less or equal_, defined on integers and dates, returns a boolean
- _greater or equal_, defined on integers and dates, returns a boolean
- _strict equal_, defined on integers, strings, byte arrays, dates, set, null, returns a boolean
- _strict not equal_, defined on integers, strings, byte arrays, dates, set, null, returns a boolean (v4 only)
- _contains_ takes a set and another value as argument, returns a boolean. Between two sets, indicates if the first set is a superset of the second one.
  between two strings, indicates a substring test.
- _prefix_, defined on strings, returns a boolean
- _suffix_, defined on strings, returns a boolean
- _regex_, defined on strings, returns a boolean
- _add_, defined on integers, returns an integer. Defined on strings, concatenates them.
- _sub_, defined on integers, returns an integer
- _mul_, defined on integers, returns an integer
- _div_, defined on integers, returns an integer
- _eager and_, defined on booleans, returns a boolean
- _eager or_, defined on booleans, returns a boolean
- _intersection_, defined on sets, return a set that is the intersection of both arguments
- _union_, defined on sets, return a set that is the union of both arguments
- _bitwiseAnd_, defined on integers, returns an integer (v4 only)
- _bitwiseOr_, defined on integers, returns an integer (v4 only)
- _bitwiseXor_, defined on integers, returns an integer (v4 only)
- _lenient equal_, defined on all types, returns a boolean (v6 only)
- _lenient not equal_, defined on all types, returns a boolean (v6 only)
- _any_, defined on sets, takes a closure term -> boolean, returns a boolean (v6 only)
- _all_, defined on sets, takes a closure term -> boolean, returns a boolean (v6 only)
- _short circuiting and_, defined on booleans, takes a closure () -> boolean, returns a boolean (v6 only)
- _short circuiting or_, defined on booleans, takes a closure () -> boolean, returns a boolean (v6 only)
- _get_, defined on arrays and maps (v6 only)  
  on arrays, takes an integer and returns the corresponding element (or `null`, if out of bounds)  
  on maps, takes either an integer or a string and returns the corresponding element (or `null`, if out of bounds)
- *external* call: implementation-defined, allows the datalog engine to call out to a function provided by the host language

Integer operations must have overflow checks. If it overflows, the expression
fails.

Strict equality fails with a type error when trying to compare different types.

Lenient equality returns false when trying to compare different types.

External calls are implementation defined. External calls carry a function name, which can be used to call a user-defined function provided to the biscuit library.

#### Example

The expression `$a + 2 < 4` will translate to the following opcodes: $a, 2, +, 4, <

Here is how it would be executed, given $a is bound to the value 1:

```
Context: a ~> 1
Op | stack
   | [ ]
$a | [ 1 ]
2  | [ 2, 1 ]
+  | [ 3 ]
4  | [ 4, 3 ]
<  | [ true ]
```

The stack contains only one value, and it is `true`: the expression succeeds.

##### Closures

The expression `[1,2].any($x -> $x == $a)` will translate to the following opcodes: [1,2], x->[$x, $a, ==], any.

Here is how it would be executed, given $a is bound to the value 2:

```
Context: a ~> 2
Op            | stack
              | [ ]
[1,2]         | [ [1,2] ]
x->[$x,$a,==] | [ x->[$x,$a,==],[1,2] ]
any           | … starting recursive evaluation …


Beginning new evaluation
Context: a ~> 2, x ~> 1
Op | stack
   | []
$x | [ 1 ]
$a | [ 2, 1 ]
== | [ false ]

The stack contains one value, false. So the evaluation must continue with the next set element.

Beggining new evaluation
Context: a ~> 2, x ~> 2
Op | stack
   | []
$x | [ 2 ]
$a | [ 2, 2 ]
== | [ true ]

The stack contains one value, true. The evaluation can stop here, the evaluation of any can return true.

Resuming parent stack
Context: a ~> 2
Op  | stack
any | true
```
The stack contains only one value, and it is `true`: the expression succeeds.

### Datalog fact generation

Datalog fact generation works by repeatedly extending a Datalog _world_ until no new facts are generated.

A Datalog world is:

- a set of _rules_, each one tagged by the block id they were defined in
- a set of _facts_, each one tagged by its _origin_: the block ids that allowed them to exist

Then, for each rule

 - facts are filtered based on their origin, and the scope annotation of the rule
 - available facts are matched on the rule predicates; only fact combinations that match every predicate are kept
 - rules expressions are computed for every matched combination; only fact combinations for which every expression returns true succeed
 - new facts are generated by the rule head, based on the matched variables

A fact defined in a block `n` has for origin `{n}` (a set containing only `n`).
A fact generated by a rule defined in block `rule_block_id` that matched on facts `fact_0…, fact_n` has for origin
  `Union({rule_block_id}, origin(fact_0) …, origin(fact_n))`.

### Verifier

The verifier provides information on the operation, such as the type of access
("read", "write", etc), the resource accessed, and more ambient data like the
current time, source IP address, revocation lists.
The verifier can also provide its own checks. It provides allow and deny policies
for the final decision on request validation.

#### Deserializing the token

The token must first be deserialized according to the protobuf format definition,
of `Biscuit`.

The cryptographic signature must be checked immediately after
deserializing. The verifier must check that the public key of the authority
block is the root public key it is expecting.

A `Biscuit` contains in its `authority` and `blocks` fields
some byte arrays that must be deserialized as a `Block`.

#### Authorization process

The authorizer will first create a default symbol table, and will append to that table the values
from the `symbols` field of each block, starting from the `authority` block and all the
following blocks, ordered by their index.

The verifier will create a Datalog "world", and add to this world its own facts and rules:
ambient data from the request, lists of users and roles, etc.

- the facts from the authority block
- the rules from the authority block
- for each following block:
  - add the facts from the block.
  - add the rules from the block.

##### Revocation identifiers

The verifier will generate a list of facts indicating revocation identifiers for
the token. The revocation identifier for a block is its signature (as it uniquely
identifies the block) serialized to a byte array (as in the Protobuf schema).
For each of these if, a fact `revocation_id(<index of the block>, <byte array>)` will be generated.

##### Authorizing

From there, the authorizer can start loading data from each block.

- load facts and rules from every block, tagging each fact and rule with the corresponding block id
- run the Datalog engine on all the facts and rules
- for each check, validate it. If it fails, add an error to the error list
- for each allow/deny policy:
  - run the query. If it succeeds:
    - if it is an allow policy, the verification succeeds, store the result and stop here
    - if it is a deny policy, the verification fails, store the result and stop here

Returning the result:

- if the error list is not empty, return the error list
- check policy result:
  - if an allow policy matched, the verification succeeds
  - if a deny policy matched, the verification fails
  - if no policy matched, the verification fails

#### Queries

The verifier can also run queries over the loaded data. A query is a datalog rule,
and the query's result is the produced facts.

### Appending

#### Deserializing

Appending a new block to an existing biscuit token requires deserializing blocks to extract symbol tables. Signature verification is not required at this step.

## Format

The current version of the format is in [schema.proto](https://github.com/biscuit-auth/biscuit/blob/master/schema.proto)

The token contains two levels of serialization. The main structure that will be
transmitted over the wire is either the normal Biscuit wrapper:

```proto
message Biscuit {
  optional uint32 rootKeyId = 1;
  required SignedBlock authority = 2;
  repeated SignedBlock blocks = 3;
  required Proof proof = 4;
}

message SignedBlock {
  required bytes block = 1;
  required PublicKey nextKey = 2;
  required bytes signature = 3;
  optional ExternalSignature externalSignature = 4;
  optional uint32 version = 5;
}

message ExternalSignature {
  required bytes signature = 1;
  required PublicKey publicKey = 2;
}

message PublicKey {
  required Algorithm algorithm = 1;

  enum Algorithm {
    Ed25519 = 0;
  }

  required bytes key = 2;
}

message Proof {
  oneof Content {
    bytes nextSecret = 1;
    bytes finalSignature = 2;
  }
}
```

The `rootKeyId` is a hint to decide which root public key should be used
for signature verification.

Each block contains a serialized byte array of the Datalog data (`block`),
the next public key (`nextKey`) and the signature of that block and key
by the previous key. The `version` field indicates the version of the signature
payload format.

The `proof` field contains either the private key corresponding to the
public key in the last block (attenuable tokens) or a signature of the last
block by the private key (sealed tokens).

The `block` field is a byte array, containing a `Block` structure serialized
in Protobuf format as well:

```proto
message Block {
  repeated string symbols = 1;
  optional string context = 2;
  optional uint32 version = 3;
  repeated FactV2 facts_v2 = 4;
  repeated RuleV2 rules_v2 = 5;
  repeated CheckV2 checks_v2 = 6;
  repeated Scope scope = 7;
  repeated PublicKey publicKeys = 8;
}
```

Each block contains a `version` field, indicating at which format version it
was generated. Since a Biscuit implementation at version N can receive a valid
token generated at version N-1, new implementations must be able to recognize
older formats. Moreover, when appending a new block, they cannot convert the
old blocks to the new format (since that would invalidate the signature). So
each block must carry its own version.

- An implementation must refuse a token containing blocks with a newer format than the range they know.
- An implementation must refuse a token containing blocks with an older format than the range they know.
- An implementation may generate blocks with older formats to help with backwards compatibility,
  when possible, especially for biscuit versions that are only additive in terms of features.

- The lowest supported biscuit version is `3`;
- The highest supported biscuit version is `5`;

# Version 2

This is the format for the 2.0 version of Biscuit.

It transport expressions as an array of opcodes.

### Text format

When transmitted as text, a Biscuit token should be serialized to a
URLS safe base 64 string. When the context does not indicate that it
is a Biscuit token, that base 64 string should be prefixed with `biscuit:`.

### Cryptography

Biscuit tokens are based on public key cryptography, with a chain of Ed25519
signatures. Each block contains the serialized Datalog, the next public key,
and the signature by the previous key. The token also contains the private key
corresponding to the last public key, to sign a new block and attenuate the
token, or a signature of the last block by the last private key, to seal the
token.

#### Signed payload generation

The data covered by the signature algorithm depends on the `version` field of
the `SignedBlock` message. If the field is absent, it defaults to version 0.

##### Version 0 (deprecated)

This defines the block signature payload v0.

The authority block signature payload v0 is the concatenation of:
- `data_0`: the serialized Datalog
- `pk_1`: the next public key
- `alg_1`: the little endian representation of the signature algorithm for `pk_1`

To sign the block at index `n+1`, the signed payload format is the concatenation of:
- `data_n+1`: the serialized Datalog
- `pk_n+2`: the next public key
- `alg_n+2`: the little endian representation of the signature algorithm for `pk_n+2`

if `external_sig_n+1` is present, the signed payload format is instead the concatenation of:
- `data_n+1`: the serialized Datalog
- `external_sig_n+1`: the optional external signature of the block
- `pk_n+2`: the next public key
- `alg_n+2`: the little endian representation of the signature algorithm for `pk_n+2`

This format is deprecated and will be replaced by version 1 in the future.

the signed payload format for external signatures, thereafter referred as "external signature payload v0", is the concatenation of:
- `data_n+1`: the serialized Datalog
- `pk_n+1`: the public key for the next block
- `alg_n+1`: the little endian representation of the signature algorithm for `pk_n+1`

This format is not supported anymore and should be replaced by version 1.

##### Version 1

This defines the block signature payload v1.

The authority block signature payload v1 is the concatenation of:
- the binary representation of the ASCII string "\0BLOCK\0"
- the binary representation of the ASCII string "\0VERSION\0"
- the little endian representation of the version of the signature payload format
- the binary representation of the ASCII string "\0PAYLOAD\0"
- `data_0`: the serialized Datalog
- the binary representation of the ASCII string "\0ALGORITHM\0"
- `alg_1`: the little endian representation of the signature algorithm for `pk_1`
- the binary representation of the ASCII string "\0NEXTKEY\0"
- `pk_1`: the next public key

To sign the block at index `n+1`, the signed payload format is the concatenation of:
- the binary representation of the ASCII string "\0BLOCK\0"
- the binary representation of the ASCII string "\0VERSION\0"
- the little endian representation of the version of the signature payload format
- the binary representation of the ASCII string "\0PAYLOAD\0"
- `data_n+1`: the serialized Datalog
- the binary representation of the ASCII string "\0ALGORITHM\0"
- `alg_n+2`: the little endian representation of the signature algorithm for `pk_n+2`
- the binary representation of the ASCII string "\0NEXTKEY\0"
- `pk_n+2`: the next public key
- the binary representation of the ASCII string "\0PREVSIG\0"
- `sig_n`: the signature of the previous block
- if `external_sig_n+1` is present:
  - the binary representation of the ASCII string "\0EXTERNALSIG\0"
  - `external_sig_n+1`: the optional external signature of the block

the signed payload format for external signatures, thereafter referred as "external signature payload v1", is the concatenation of:
- the binary representation of the ASCII string "\0EXTERNAL\0"
- the binary representation of the ASCII string "\0VERSION\0"
- the little endian representation of the version of the signature payload format
- the binary representation of the ASCII string "\0PAYLOAD\0"
- `data_n+1`: the serialized Datalog
- the binary representation of the ASCII string "\0PREVSIG\0"
- `sig_n`: the signature of the previous block

#### Signature (one block)

- `(pk_0, sk_0)` the root public and private Ed25519 keys
- `data_0` the serialized Datalog
- `(pk_1, sk_1)` the next key pair, generated at random
- `alg_1` the little endian representation of the signature algorithm fr `pk1, sk1` (see protobuf schema)
- the signed block version indicates the version of the signature payload format, either "block signature payload v0" or "block signature payload v1"
-  `sig_0` is the signature of the payload by `sk_0`

The token will contain:

```
Token {
  root_key_id: <optional number indicating the root key to use for verification>
  authority: Block {
    data_0,
    pk_1,
    sig_0,
  }
  blocks: [],
  proof: Proof {
    nextSecret: sk_1,
  },
}
```

#### Signature (appending)

With a token containing blocks 0 to n:

Block n contains:

- `data_n`
- `pk_n+1`
- `sig_n`

The token also contains `sk_n+1`.

The new block can optionally be signed by an external keypair `(epk, esk)` and carry an external signature `esig`.

the signed block version indicates the version of the signature payload format, either "block signature payload v0" or "block signature payload v1".

We generate at random `(pk_n+2, sk_n+2)` and the signature `sig_n+1` is the signature of the payload by `sk_n+1`.

The token will contain:

```
Token {
  root_key_id: <optional number indicating the root key to use for verification>
  authority: Block_0,
  blocks: [Block_1, .., Block_n,
      Block_n+1 {
      data_n+1,
      pk_n+2,
      sig_n+1,
      epk?, esig?
    }]
  proof: Proof {
    nextSecret: sk_n+2,
  },
}
```

##### Optional external signature

Blocks generated by a trusted third party can carry an *extra* signature to provide a proof of their
origin. Same as regular signatures, they rely on Ed25519.

The external signature for block `n+1`, with `(external_pk, external_sk)` is `external_sig_n+1`, the signature of the payload in format "external signature payload v1" by `external_sk`.
The authority block can't carry an external signature. This is necessary to make sure an external signature can't be used for any other token.

The presence of an external signature affects the regular signature: the external signature is part of the payload signed by the regular signature.

The token will contain:

```
Token {
  root_key_id: <optional number indicating the root key to use for verification>
  authority: Block_0,
  blocks: [Block_1, .., Block_n,
      Block_n+1 {
      data_n+1,
      pk_n+2,
      sig_n+1,
      external_pk,
      external_sig_n+1
    }]
  proof: Proof {
    nextSecret: sk_n+2,
  },
}
```

#### Verifying

For each block i from 0 to n:
- `payload_i`: the signature payload for block i
- `verify(pk_i, sig_i, payload_i)`

If all signatures are verified, extract pk_n+1 from the last block and
sk_n+1 from the proof field, and check that they are from the same
key pair.

##### Verifying external signatures

For each block i from 1 to n, _where an external signature is present_:
- `external_payload_i`: the external signature payload for block i
- `verify(external_pk_i, external_sig_i, external_payload_i)`

#### Signature (sealing)

With a token containing blocks 0 to n:

Block n contains:

- `data_n`
- `pk_n+1`
- `sig_n`

The token also contains `sk_n+1`

We generate the signature `sig_n+1 = sign(sk_n+1, data_n + alg_n+1 + pk_n+1 + sig_n)` (we sign
the last block and its signature with the last private key).

The token will contain:

```
Token {
  root_key_id: <optional number indicating the root key to use for verification>
  authority: Block_0,
  blocks: [Block_1, .., Block_n]
  proof: Proof {
    finalSignature: sig_n+1
  },
}
```

#### Verifying (sealed)

For each block i from 0 to n:

- verify(pk_i, sig_i, data_i+alg_i+1+pk_i+1)

If all signatures are verified, extract pk_n+1 from the last block and
sig from the proof field, and check `verify(pk_n+1, sig_n+1, data_n+alg_n+1+pk_n+1+sig_n)`

### Blocks

A block is defined as follows in the schema file:

```proto
message Block {
  repeated string symbols = 1;
  optional string context = 2;
  optional uint32 version = 3;
  repeated FactV2 facts_v2 = 4;
  repeated RuleV2 rules_v2 = 5;
  repeated CheckV2 checks_v2 = 6;
  repeated Scope scope = 7;
  repeated PublicKey publicKeys = 8;
}
```

The block index is incremented for each new block. The Block 0
is the authority block.

Each block can provide facts either from its facts list, or generate
them with its rules list.

### Symbol table

To reduce the token size and improve performance, Biscuit uses a symbol table,
a list of strings that any fact or token can refer to by index. While
running the logic engine does not need to know the content of that list,
pretty printing facts, rules and results will use it.

The symbol table is created from a default table containing, in order:

- read
- write
- resource
- operation
- right
- time
- role
- owner
- tenant
- namespace
- user
- team
- service
- admin
- email
- group
- member
- ip_address
- client
- client_ip
- domain
- path
- version
- cluster
- node
- hostname
- nonce
- query

Symbol table indexes from 0 to 1023 are reserved for the default symbols. Symbols
defined in a token or authorizer must start from 1024.

#### Adding content to the symbol table

##### Regular blocks (no external signature)

When creating a new block, we start from the current symbol table of the token.
For each fact or rule that introduces a new symbol, we add the corresponding
string to the table, and convert the fact or rule to use its index instead.

Once every fact and rule has been integrated, we set as the block's symbol table
(its `symbols` field) the symbols that were appended to the token's table.

The new token's symbol table is the list from the default table, and for each
block in order, the block's symbols.

It is important to verify that different blocks do not contain the same symbol in
their list.

##### 3rd party blocks (with an external signature)

Blocks that are signed by an external key don't use the token symbol table
and start from the default symbol table. Following blocks ignore the symbols
declared in their `symbols` field.

The reason for this is that the party signing the block is not supposed to have
access to the token itself and can't use the token's symbol table.

### Public key tables

Public keys carried in `SignedBlock`s are stored as is, as they are required for verification.

Public keys carried in datalog scope annotations are stored in a table, to reduce token size.

Public keys are interned the same way for first-party and third-party tokens, unlike symbols.

#### Reading

Building a symbol table for a token can be done this way:

for each block:

- add the external public key if defined (and if not already present)
- add the contents of the `publicKeys` field of the `Block` message

It is important to only add the external public key if it's not already
present, to avoid having it twice in the symbol table.

#### Appending

Same as for symbols, the `publicKeys` field should only contain public keys
that were not present in the table yet.

## Appending a third-party block

Third party blocks are special blocks, that are meant to be signed by a trusted party, to either expand a token or fulfill special checks with dedicated public key constraints.

Unlike first-party blocks, the party signing the token should not have access to the token itself. The third party needs however some context in order to be able to properly serialize and sign block contents. Additionally, the third party needs to return both the serialized block and the external signature.

To support this use-case, the protobuf schema defines two message types: `ThirdPartyBlockRequest` and `ThirdPartyBlockContents`:

```
message ThirdPartyBlockRequest {
  required PublicKey previousKey = 1;
  repeated PublicKey publicKeys = 2;
  required bytes previousSignature = 3;
}

message ThirdPartyBlockContents {
  required bytes payload = 1;
  required ExternalSignature externalSignature = 2;
}
```

`ThirdPartyBlockRequest` contains the necessary context for serializing and signing a datalog block:

- `previousKey` is needed for the signature (it makes sure that a third-party block can only be used for a specific biscuit token
- `publicKeys` is the list of public keys already present in the token table; they are used for serialization

`ThirdPartyBlockContents` contains both the serialized `Block` and the external signature.

The expected sequence is

- the token holder generates a `ThirdPartyBlockRequest` from their token;
- they send it, along with domain-specific information, to the third party that's responsible for providing a third-party block;
- the third party creates a datalog block (based on domain-specific information), serializes it and signs it, and returns
  a `ThirdPartyBlockContents` to the token holder
- the token holder now uses `ThirdPartyBlockContents` to append a new signed block to the token

An implementation must be able to:

- generate a `ThirdPartyBlockRequest` from a token (by extracting its last ephemeral public key and its public key table)
- apply a `ThirdPartyBlockContents` on a token by appending the serialized block like a regular block

Same as biscuit tokens, the `ThirdPartyBlockRequest` and `ThirdPartyBlockContents` values can be transfered in text format
by encoding them with base64url.

## Test cases

We provide sample tokens and the expected result of their verification at
[https://github.com/biscuit-auth/biscuit/tree/master/samples](https://github.com/CleverCloud/biscuit/tree/master/samples)

## References

- "Trust Management Languages" https://www.cs.purdue.edu/homes/ninghui/papers/cdatalog_padl03.pdf

[^protobuf]: ProtoBuf https://developers.google.com/protocol-buffers/
[^datalog]: "Datalog with Constraints: A Foundation for Trust Management Languages" http://crypto.stanford.edu/~ninghui/papers/cdatalog_padl03.pdf
[^macaroons]: "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud" https://ai.google/research/pubs/pub41892
