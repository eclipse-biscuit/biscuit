# Biscuit samples and expected results

root secret key: 99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61
root public key: 1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284

------------------------------

## basic token: test001_basic.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

block version: 3

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

block version: 3

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

authorizer code:
```
resource("file1");

allow if true;
```

revocation ids:
- `7595a112a1eb5b81a6e398852e6118b7f5b8cbbff452778e655100e5fb4faa8d3a2af52fe2c4f9524879605675fae26adbc4783e0cafc43522fa82385f396c03`
- `45f4c14f9d9e8fa044d68be7a2ec8cddb835f575c7b913ec59bd636c70acae9a90db9064ba0b3084290ed0c422bbb7170092a884f5e0202b31e9235bbcc1650d`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "resource(\"file1\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"file1\", \"read\")",
            "right(\"file1\", \"write\")",
            "right(\"file2\", \"read\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if resource($0), operation(\"read\"), right($0, \"read\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($0), operation(\"read\"), right($0, \"read\")" })] }))`


------------------------------

## different root key: test002_different_root_key.bc
### token

authority:
symbols: ["file1"]

public keys: []

block version: 3

```
right("file1", "read");
```

1:
symbols: ["0"]

public keys: []

block version: 3

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## invalid signature format: test003_invalid_signature_format.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

block version: 3

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

block version: 3

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(BlockSignatureDeserializationError("block signature deserialization error: [117, 149, 161, 18, 161, 235, 91, 129, 166, 227, 152, 133, 46, 97, 24, 183]")))`


------------------------------

## random block: test004_random_block.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

block version: 3

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

block version: 3

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## invalid signature: test005_invalid_signature.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

block version: 3

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

block version: 3

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## reordered blocks: test006_reordered_blocks.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

block version: 3

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

block version: 3

```
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: []

public keys: []

block version: 3

```
check if resource("file1");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## scoped rules: test007_scoped_rules.bc
### token

authority:
symbols: ["user_id", "alice", "file1"]

public keys: []

block version: 3

```
user_id("alice");
owner("alice", "file1");
```

1:
symbols: ["0", "1"]

public keys: []

block version: 3

```
right($0, "read") <- resource($0), user_id($1), owner($1, $0);
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: ["file2"]

public keys: []

block version: 3

```
owner("alice", "file2");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

allow if true;
```

revocation ids:
- `4d86c9af808dc2e0583f47282e6f5df3e09dc264d5231ec360b4519e15ddaeec60b25a9bbcb22e8d192f4d36a0da3f9243711e30535b00ee55c53cb1395f230a`
- `63208c668c66f3ba6927140ba37533593b25e03459447805d4b2a8b75adeef45794c3d7249afe506ed77ccee276160bb4052a4009302bd34871a440f070b4509`
- `d8da982888eae8c038e4894a8c06fc57d8e5f06ad2e972b9cf4bde49ad60804558a0d1938192596c702d8e4f7f12ec19201d7c33d0cd77774a0d879a33880d02`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file2\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "owner(\"alice\", \"file1\")",
            "user_id(\"alice\")",
        ],
    },
    Facts {
        origin: {
            Some(
                2,
            ),
        },
        facts: [
            "owner(\"alice\", \"file2\")",
        ],
    },
]
  rules: [
    Rules {
        origin: Some(
            1,
        ),
        rules: [
            "right($0, \"read\") <- resource($0), user_id($1), owner($1, $0)",
        ],
    },
]
  checks: [
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if resource($0), operation(\"read\"), right($0, \"read\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($0), operation(\"read\"), right($0, \"read\")" })] }))`


------------------------------

## scoped checks: test008_scoped_checks.bc
### token

authority:
symbols: ["file1"]

public keys: []

block version: 3

```
right("file1", "read");
```

1:
symbols: ["0"]

public keys: []

block version: 3

```
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: ["file2"]

public keys: []

block version: 3

```
right("file2", "read");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

allow if true;
```

revocation ids:
- `a80c985ddef895518c216f64c65dcd50a5d97d012a94453d79159aed2981654b1fe9748c686c5667604026a94fb8db8a1d02de747df61e99fa9a63ff2878ad00`
- `77df45442be86a416aa02fd9d98d6d4703c634a9e3b1d293b41f5dc97849afbe7faeec8c22a210574888acc008fb64fe691ec9e8d2655586f970d9a6b6577000`
- `b31398aefe97d3db41ebc445760f216fb3aa7bf7439adcfc3a07489bfcc163970af3f4e20f5460aa24cf841101a5ab114d21acc0ee8d442bae7793b121284900`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file2\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"file1\", \"read\")",
        ],
    },
    Facts {
        origin: {
            Some(
                2,
            ),
        },
        facts: [
            "right(\"file2\", \"read\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if resource($0), operation(\"read\"), right($0, \"read\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($0), operation(\"read\"), right($0, \"read\")" })] }))`


------------------------------

## expired token: test009_expired_token.bc
### token

authority:
symbols: []

public keys: []

block version: 3

```
```

1:
symbols: ["file1"]

public keys: []

block version: 3

```
check if resource("file1");
check if time($time), $time <= 2018-12-20T00:00:00Z;
```

### validation

authorizer code:
```
resource("file1");
operation("read");
time(2020-12-21T09:23:12Z);

allow if true;
```

revocation ids:
- `c248907bb6e5f433bbb5edf6367b399ebefca0d321d0b2ea9fc67f66dc1064ce926adb0c05d90c3e8a2833328b3578f79c4e1bca43583d9bcfb2ba6c37303d00`
- `a4edf7aaea8658bb9ae19b3ffe2adcc77cc9f16c249aeb0a85a584b5362f89f27f7c67ac0af16d7170673d6d1fb1563d1934b25ec5a461f6c01fa49805cd5e07`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file1\")",
            "time(2020-12-21T09:23:12Z)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if resource(\"file1\")",
            "check if time($time), $time <= 2018-12-20T00:00:00Z",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 1, rule: "check if time($time), $time <= 2018-12-20T00:00:00Z" })] }))`


------------------------------

## authorizer scope: test010_authorizer_scope.bc
### token

authority:
symbols: ["file1"]

public keys: []

block version: 3

```
right("file1", "read");
```

1:
symbols: ["file2"]

public keys: []

block version: 3

```
right("file2", "read");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

check if right($0, $1), resource($0), operation($1);

allow if true;
```

revocation ids:
- `a80c985ddef895518c216f64c65dcd50a5d97d012a94453d79159aed2981654b1fe9748c686c5667604026a94fb8db8a1d02de747df61e99fa9a63ff2878ad00`
- `966eceb2aa937c41b25368808bab6e0698c02a4038de669d007c9c3d43602638a640083558d1576ac80cf3eb2ac6a7585527e0f6c1a65402f0935cf7f4df8005`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file2\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"file1\", \"read\")",
        ],
    },
    Facts {
        origin: {
            Some(
                1,
            ),
        },
        facts: [
            "right(\"file2\", \"read\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            18446744073709551615,
        ),
        checks: [
            "check if right($0, $1), resource($0), operation($1)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Authorizer(FailedAuthorizerCheck { check_id: 0, rule: "check if right($0, $1), resource($0), operation($1)" })] }))`


------------------------------

## authorizer authority checks: test011_authorizer_authority_caveats.bc
### token

authority:
symbols: ["file1"]

public keys: []

block version: 3

```
right("file1", "read");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

check if right($0, $1), resource($0), operation($1);

allow if true;
```

revocation ids:
- `a80c985ddef895518c216f64c65dcd50a5d97d012a94453d79159aed2981654b1fe9748c686c5667604026a94fb8db8a1d02de747df61e99fa9a63ff2878ad00`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file2\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"file1\", \"read\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            18446744073709551615,
        ),
        checks: [
            "check if right($0, $1), resource($0), operation($1)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Authorizer(FailedAuthorizerCheck { check_id: 0, rule: "check if right($0, $1), resource($0), operation($1)" })] }))`


------------------------------

## authority checks: test012_authority_caveats.bc
### token

authority:
symbols: ["file1"]

public keys: []

block version: 3

```
check if resource("file1");
```

### validation for "file1"

authorizer code:
```
resource("file1");
operation("read");

allow if true;
```

revocation ids:
- `6a8f90dad67ae2ac188460463914ae7326fda431c80785755f4edcc15f1a53911f7366e606ad80cbbeba94672e42713e88632a932128f1d796ce9ba7d7a0b80a`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file1\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if resource(\"file1\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`
### validation for "file2"

authorizer code:
```
resource("file2");
operation("read");

allow if true;
```

revocation ids:
- `6a8f90dad67ae2ac188460463914ae7326fda431c80785755f4edcc15f1a53911f7366e606ad80cbbeba94672e42713e88632a932128f1d796ce9ba7d7a0b80a`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file2\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if resource(\"file1\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource(\"file1\")" })] }))`


------------------------------

## block rules: test013_block_rules.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

block version: 3

```
right("file1", "read");
right("file2", "read");
```

1:
symbols: ["valid_date", "0", "1"]

public keys: []

block version: 3

```
valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59Z;
valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, !{"file1"}.contains($1);
check if valid_date($0), resource($0);
```

### validation for "file1"

authorizer code:
```
resource("file1");
time(2020-12-21T09:23:12Z);

allow if true;
```

revocation ids:
- `c46d071ff3f33434223c8305fdad529f62bf78bb5d9cbfc2a345d4bca6bf314014840e18ba353f86fdb9073d58b12b8c872ac1f8e593c2e9064b90f6c2ede006`
- `a0c4c163a0b3ca406df4ece3d1371356190df04208eccef72f77e875ed0531b5d37e243d6f388b1967776a5dfd16ef228f19c5bdd6d2820f145c5ed3c3dcdc00`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "resource(\"file1\")",
            "time(2020-12-21T09:23:12Z)",
        ],
    },
    Facts {
        origin: {
            None,
            Some(
                1,
            ),
        },
        facts: [
            "valid_date(\"file1\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"file1\", \"read\")",
            "right(\"file2\", \"read\")",
        ],
    },
]
  rules: [
    Rules {
        origin: Some(
            1,
        ),
        rules: [
            "valid_date(\"file1\") <- time($0), resource(\"file1\"), $0 <= 2030-12-31T12:59:59Z",
            "valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, !{\"file1\"}.contains($1)",
        ],
    },
]
  checks: [
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if valid_date($0), resource($0)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`
### validation for "file2"

authorizer code:
```
resource("file2");
time(2020-12-21T09:23:12Z);

allow if true;
```

revocation ids:
- `c46d071ff3f33434223c8305fdad529f62bf78bb5d9cbfc2a345d4bca6bf314014840e18ba353f86fdb9073d58b12b8c872ac1f8e593c2e9064b90f6c2ede006`
- `a0c4c163a0b3ca406df4ece3d1371356190df04208eccef72f77e875ed0531b5d37e243d6f388b1967776a5dfd16ef228f19c5bdd6d2820f145c5ed3c3dcdc00`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "resource(\"file2\")",
            "time(2020-12-21T09:23:12Z)",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"file1\", \"read\")",
            "right(\"file2\", \"read\")",
        ],
    },
]
  rules: [
    Rules {
        origin: Some(
            1,
        ),
        rules: [
            "valid_date(\"file1\") <- time($0), resource(\"file1\"), $0 <= 2030-12-31T12:59:59Z",
            "valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, !{\"file1\"}.contains($1)",
        ],
    },
]
  checks: [
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if valid_date($0), resource($0)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if valid_date($0), resource($0)" })] }))`


------------------------------

## regex_constraint: test014_regex_constraint.bc
### token

authority:
symbols: ["0", "file[0-9]+.txt"]

public keys: []

block version: 3

```
check if resource($0), $0.matches("file[0-9]+.txt");
```

### validation for "file1"

authorizer code:
```
resource("file1");

allow if true;
```

revocation ids:
- `da42718ad2631c12d3a44b7710dcc76c6c7809c6bc3a2d7eb0378c4154eae10e0884a8d54a2cd25ca3dfe01091d816ebbb9d246227baf7a359a787cb2344ad07`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "resource(\"file1\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if resource($0), $0.matches(\"file[0-9]+.txt\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource($0), $0.matches(\"file[0-9]+.txt\")" })] }))`
### validation for "file123"

authorizer code:
```
resource("file123.txt");

allow if true;
```

revocation ids:
- `da42718ad2631c12d3a44b7710dcc76c6c7809c6bc3a2d7eb0378c4154eae10e0884a8d54a2cd25ca3dfe01091d816ebbb9d246227baf7a359a787cb2344ad07`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "resource(\"file123.txt\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if resource($0), $0.matches(\"file[0-9]+.txt\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## multi queries checks: test015_multi_queries_caveats.bc
### token

authority:
symbols: ["must_be_present", "hello"]

public keys: []

block version: 3

```
must_be_present("hello");
```

### validation

authorizer code:
```
check if must_be_present($0) or must_be_present($0);

allow if true;
```

revocation ids:
- `b0d466d31e015fa85a075fa875f7e1c9017edd503fee9f62a5f033e1fcfa811074b6e39dfe5af2f452043db97a3f98650592a370f5685b62c5d6abf9dd10b603`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "must_be_present(\"hello\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            18446744073709551615,
        ),
        checks: [
            "check if must_be_present($0) or must_be_present($0)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## check head name should be independent from fact names: test016_caveat_head_name.bc
### token

authority:
symbols: ["hello"]

public keys: []

block version: 3

```
check if resource("hello");
```

1:
symbols: ["test"]

public keys: []

block version: 3

```
query("test");
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `ce6f804f4390e693a8853d9a4a10bd4f3c94b86b7c6d671993a6e19346bc4d20bbb52cc945e5d0d02e4e75fa5da2caa99764050190353564a0a0b4b276809402`
- `916d566cc724e0773046fc5266e9d0d804311435b8d6955b332f823ab296be9a78dfea190447732ac9f6217234cf5726becf88f65169c6de56a766af55451b0f`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            Some(
                1,
            ),
        },
        facts: [
            "query(\"test\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if resource(\"hello\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource(\"hello\")" })] }))`


------------------------------

## test expression syntax and all available operations: test017_expressions.bc
### token

authority:
symbols: ["hello world", "hello", "world", "aaabde", "a*c?.e", "abd", "aaa", "b", "de", "abcD12", "é", "abc", "def"]

public keys: []

block version: 3

```
check if true;
check if !false;
check if true === true;
check if false === false;
check if 1 < 2;
check if 2 > 1;
check if 1 <= 2;
check if 1 <= 1;
check if 2 >= 1;
check if 2 >= 2;
check if 3 === 3;
check if 1 + 2 * 3 - 4 / 2 === 5;
check if "hello world".starts_with("hello"), "hello world".ends_with("world");
check if "aaabde".matches("a*c?.e");
check if "aaabde".contains("abd");
check if "aaabde" === "aaa" + "b" + "de";
check if "abcD12" === "abcD12";
check if "abcD12".length() === 6;
check if "é".length() === 2;
check if 2019-12-04T09:46:41Z < 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z > 2019-12-04T09:46:41Z;
check if 2019-12-04T09:46:41Z <= 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z >= 2019-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z === 2020-12-04T09:46:41Z;
check if hex:12ab === hex:12ab;
check if {1, 2}.contains(2);
check if {2019-12-04T09:46:41Z, 2020-12-04T09:46:41Z}.contains(2020-12-04T09:46:41Z);
check if {false, true}.contains(true);
check if {"abc", "def"}.contains("abc");
check if {hex:12ab, hex:34de}.contains(hex:34de);
check if {1, 2}.contains({2});
check if {1, 2} === {1, 2};
check if {1, 2}.intersection({2, 3}) === {2};
check if {1, 2}.union({2, 3}) === {1, 2, 3};
check if {1, 2, 3}.intersection({1, 2}).contains(1);
check if {1, 2, 3}.intersection({1, 2}).length() === 2;
check if {,}.length() === 0;
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `fa358e4e3bea896415b1859e6cd347e64e1918fb86e31ae3fe208628321576a47f7a269760357e291c827ec9cbe322074f6860a546207a64e133c83a214bb505`

authorizer world:
```
World {
  facts: []
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if !false",
            "check if \"aaabde\" === \"aaa\" + \"b\" + \"de\"",
            "check if \"aaabde\".contains(\"abd\")",
            "check if \"aaabde\".matches(\"a*c?.e\")",
            "check if \"abcD12\" === \"abcD12\"",
            "check if \"abcD12\".length() === 6",
            "check if \"hello world\".starts_with(\"hello\"), \"hello world\".ends_with(\"world\")",
            "check if \"é\".length() === 2",
            "check if 1 + 2 * 3 - 4 / 2 === 5",
            "check if 1 < 2",
            "check if 1 <= 1",
            "check if 1 <= 2",
            "check if 2 > 1",
            "check if 2 >= 1",
            "check if 2 >= 2",
            "check if 2019-12-04T09:46:41Z < 2020-12-04T09:46:41Z",
            "check if 2019-12-04T09:46:41Z <= 2020-12-04T09:46:41Z",
            "check if 2020-12-04T09:46:41Z === 2020-12-04T09:46:41Z",
            "check if 2020-12-04T09:46:41Z > 2019-12-04T09:46:41Z",
            "check if 2020-12-04T09:46:41Z >= 2019-12-04T09:46:41Z",
            "check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z",
            "check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z",
            "check if 3 === 3",
            "check if false === false",
            "check if hex:12ab === hex:12ab",
            "check if true",
            "check if true === true",
            "check if {\"abc\", \"def\"}.contains(\"abc\")",
            "check if {,}.length() === 0",
            "check if {1, 2, 3}.intersection({1, 2}).contains(1)",
            "check if {1, 2, 3}.intersection({1, 2}).length() === 2",
            "check if {1, 2} === {1, 2}",
            "check if {1, 2}.contains(2)",
            "check if {1, 2}.contains({2})",
            "check if {1, 2}.intersection({2, 3}) === {2}",
            "check if {1, 2}.union({2, 3}) === {1, 2, 3}",
            "check if {2019-12-04T09:46:41Z, 2020-12-04T09:46:41Z}.contains(2020-12-04T09:46:41Z)",
            "check if {false, true}.contains(true)",
            "check if {hex:12ab, hex:34de}.contains(hex:34de)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## invalid block rule with unbound_variables: test018_unbound_variables_in_rule.bc
### token

authority:
symbols: []

public keys: []

block version: 3

```
check if operation("read");
```

1:
symbols: ["unbound", "any1", "any2"]

public keys: []

block version: 3

```
operation($unbound, "read") <- operation($any1, $any2);
```

### validation

result: `Err(FailedLogic(InvalidBlockRule(0, "operation($unbound, \"read\") <- operation($any1, $any2)")))`


------------------------------

## invalid block rule generating an #authority or #ambient symbol with a variable: test019_generating_ambient_from_variables.bc
### token

authority:
symbols: []

public keys: []

block version: 3

```
check if operation("read");
```

1:
symbols: ["any"]

public keys: []

block version: 3

```
operation("read") <- operation($any);
```

### validation

authorizer code:
```
operation("write");

allow if true;
```

revocation ids:
- `a44210c6a01e55eadefc7d8540c2e6eff80ab6eeedde4751de734f9d780435780680d3f42d826b7e0f0dcf4a5ba303fd4c116984bb30978813d46ed867924307`
- `d3f8822a9b9bc0ee3933283c493ca9e711be5dd8339b5fe2eba1de3805aad4e84d3e2fb4affb4a743f1289915c167582b9425343635e45b70573ea1ee7a1ea03`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"write\")",
        ],
    },
    Facts {
        origin: {
            None,
            Some(
                1,
            ),
        },
        facts: [
            "operation(\"read\")",
        ],
    },
]
  rules: [
    Rules {
        origin: Some(
            1,
        ),
        rules: [
            "operation(\"read\") <- operation($any)",
        ],
    },
]
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if operation(\"read\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if operation(\"read\")" })] }))`


------------------------------

## sealed token: test020_sealed.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

block version: 3

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

block version: 3

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

authorizer code:
```
resource("file1");
operation("read");

allow if true;
```

revocation ids:
- `7595a112a1eb5b81a6e398852e6118b7f5b8cbbff452778e655100e5fb4faa8d3a2af52fe2c4f9524879605675fae26adbc4783e0cafc43522fa82385f396c03`
- `45f4c14f9d9e8fa044d68be7a2ec8cddb835f575c7b913ec59bd636c70acae9a90db9064ba0b3084290ed0c422bbb7170092a884f5e0202b31e9235bbcc1650d`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file1\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"file1\", \"read\")",
            "right(\"file1\", \"write\")",
            "right(\"file2\", \"read\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if resource($0), operation(\"read\"), right($0, \"read\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## parsing: test021_parsing.bc
### token

authority:
symbols: ["ns::fact_123", "hello é\t😁"]

public keys: []

block version: 3

```
ns::fact_123("hello é	😁");
```

### validation

authorizer code:
```
check if ns::fact_123("hello é	😁");

allow if true;
```

revocation ids:
- `d4b2f417b6e906434fdf5058afcabfcb98d3628f814f1c9dd7e64250d9beec4465aff51bd0cb2e85d0e67dc9f613c2a42af6158c678bc6f8b4684cd3a2d0d302`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "ns::fact_123(\"hello é\t😁\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            18446744073709551615,
        ),
        checks: [
            "check if ns::fact_123(\"hello é\t😁\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## default_symbols: test022_default_symbols.bc
### token

authority:
symbols: []

public keys: []

block version: 3

```
read(0);
write(1);
resource(2);
operation(3);
right(4);
time(5);
role(6);
owner(7);
tenant(8);
namespace(9);
user(10);
team(11);
service(12);
admin(13);
email(14);
group(15);
member(16);
ip_address(17);
client(18);
client_ip(19);
domain(20);
path(21);
version(22);
cluster(23);
node(24);
hostname(25);
nonce(26);
query(27);
```

### validation

authorizer code:
```
check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27);

allow if true;
```

revocation ids:
- `75ce48d496fd28f99905901783a1ba46d7ff8d69f9d364d1546fd73006026eae51849ad1190a4ae521a0a1269f9c6951e226afba8fcd24fa50f679162439ae09`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "admin(13)",
            "client(18)",
            "client_ip(19)",
            "cluster(23)",
            "domain(20)",
            "email(14)",
            "group(15)",
            "hostname(25)",
            "ip_address(17)",
            "member(16)",
            "namespace(9)",
            "node(24)",
            "nonce(26)",
            "operation(3)",
            "owner(7)",
            "path(21)",
            "query(27)",
            "read(0)",
            "resource(2)",
            "right(4)",
            "role(6)",
            "service(12)",
            "team(11)",
            "tenant(8)",
            "time(5)",
            "user(10)",
            "version(22)",
            "write(1)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            18446744073709551615,
        ),
        checks: [
            "check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## execution scope: test023_execution_scope.bc
### token

authority:
symbols: ["authority_fact"]

public keys: []

block version: 3

```
authority_fact(1);
```

1:
symbols: ["block1_fact"]

public keys: []

block version: 3

```
block1_fact(1);
```

2:
symbols: ["var"]

public keys: []

block version: 3

```
check if authority_fact($var);
check if block1_fact($var);
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `f9b49866caef5ece7be14ec5a9b36d98ca81d06b306eb0b4c57cd7436af176f40ee972f40903f87ec4460ab8b1adfcbfa9b19b20a6955a1e8dae7d88b2076005`
- `889054b9119e4440e54da1b63266a98d0f6646cde195fef206efd8b133cfb2ee7be49b32a9a5925ece452e64f9e6f6d80dab422e916c599675dd68cdea053802`
- `0a85ffbf27e08aa23665ba0d96a985b274d747556c9f016fd7f590c641ed0e4133291521aa442b320ee9ce80f5ad701b914a0c87b3dfa0cc92629dce94201806`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "authority_fact(1)",
        ],
    },
    Facts {
        origin: {
            Some(
                1,
            ),
        },
        facts: [
            "block1_fact(1)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            2,
        ),
        checks: [
            "check if authority_fact($var)",
            "check if block1_fact($var)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 2, check_id: 1, rule: "check if block1_fact($var)" })] }))`


------------------------------

## third party: test024_third_party.bc
### token

authority:
symbols: []

public keys: ["ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"]

block version: 4

```
right("read");
check if group("admin") trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

1:
symbols: []

public keys: []

external signature by: "ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

block version: 5

```
group("admin");
check if right("read");
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `470e4bf7aa2a01ab39c98150bd06aa15b4aa5d86509044a8809a8634cd8cf2b42269a51a774b65d10bac9369d013070b00187925196a8e680108473f11cf8f03`
- `901b2af4dacf33458d2d91ac484b60bad948e8d10faa9695b096054d5b46e832a977b60b17464cacf545ad0801f549ea454675f0ac88c413406925e2af83ff08`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"read\")",
        ],
    },
    Facts {
        origin: {
            Some(
                1,
            ),
        },
        facts: [
            "group(\"admin\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if group(\"admin\") trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
        ],
    },
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if right(\"read\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## block rules: test025_check_all.bc
### token

authority:
symbols: ["allowed_operations", "A", "B", "op", "allowed"]

public keys: []

block version: 4

```
allowed_operations({"A", "B"});
check all operation($op), allowed_operations($allowed), $allowed.contains($op);
```

### validation for "A, B"

authorizer code:
```
operation("A");
operation("B");

allow if true;
```

revocation ids:
- `c456817012e1d523c6d145b6d6a3475d9f7dd4383c535454ff3f745ecf4234984ce09b9dec0551f3d783abe850f826ce43b12f1fd91999a4753a56ecf4c56d0d`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"A\")",
            "operation(\"B\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "allowed_operations({\"A\", \"B\"})",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check all operation($op), allowed_operations($allowed), $allowed.contains($op)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`
### validation for "A, invalid"

authorizer code:
```
operation("A");
operation("invalid");

allow if true;
```

revocation ids:
- `c456817012e1d523c6d145b6d6a3475d9f7dd4383c535454ff3f745ecf4234984ce09b9dec0551f3d783abe850f826ce43b12f1fd91999a4753a56ecf4c56d0d`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"A\")",
            "operation(\"invalid\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "allowed_operations({\"A\", \"B\"})",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check all operation($op), allowed_operations($allowed), $allowed.contains($op)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check all operation($op), allowed_operations($allowed), $allowed.contains($op)" })] }))`


------------------------------

## public keys interning: test026_public_keys_interning.bc
### token

authority:
symbols: []

public keys: ["ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"]

block version: 4

```
query(0);
check if true trusting previous, ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

1:
symbols: []

public keys: ["ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463", "ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"]

external signature by: "ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

block version: 5

```
query(1);
query(1, 2) <- query(1), query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

2:
symbols: []

public keys: ["ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463", "ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"]

external signature by: "ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463"

block version: 5

```
query(2);
check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

3:
symbols: []

public keys: ["ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463", "ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"]

external signature by: "ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463"

block version: 5

```
query(3);
check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
```

4:
symbols: []

public keys: ["ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463", "ed25519/f98da8c1cf907856431bfc3dc87531e0eaadba90f919edc232405b85877ef136"]

block version: 4

```
query(4);
check if query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;
check if query(4) trusting ed25519/f98da8c1cf907856431bfc3dc87531e0eaadba90f919edc232405b85877ef136;
```

### validation

authorizer code:
```
check if query(1, 2) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189, ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;

deny if query(3);
deny if query(1, 2);
deny if query(0) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
allow if true;
```

revocation ids:
- `3771cefe71beb21ead35a59c8116ee82627a5717c0295f35980662abccb159fe1b37848cb1818e548656bd4fd882d0094a2daab631c76b2b72e3a093914bfe04`
- `7113d4dbb3b688b80e941f365a2c6342d480c77ed03937bccf85dc5cc3554c7517887b1b0c9021388a71e6ca9047aabaaad5ae5b511a2880902568444a98e50b`
- `d0e3fc4bbd1b7320022800af909585aa906f677c4ca79c275a10b6779f669384c464ee84a1b04f13877a25761a874748362c065f4d15a8cab5c5e16c34074403`
- `29b7e0a1f118a6185814a552660c516c43482044e280e7a8de85b8e7e54947e0ae82eb39d7b524d4b72cb9812a7a4b8871964f8f825b1c1ed85d344c05281d0d`
- `c0a505d4d921a8b2d0b885917d42e2bca87b5302d13249a61af6f3802af44d691c40a624f901d677724740cb974a188aeb1c3992c1565ac0fbec3aa4f68dac0a`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "query(0)",
        ],
    },
    Facts {
        origin: {
            Some(
                1,
            ),
        },
        facts: [
            "query(1)",
        ],
    },
    Facts {
        origin: {
            Some(
                1,
            ),
            Some(
                2,
            ),
        },
        facts: [
            "query(1, 2)",
        ],
    },
    Facts {
        origin: {
            Some(
                2,
            ),
        },
        facts: [
            "query(2)",
        ],
    },
    Facts {
        origin: {
            Some(
                3,
            ),
        },
        facts: [
            "query(3)",
        ],
    },
    Facts {
        origin: {
            Some(
                4,
            ),
        },
        facts: [
            "query(4)",
        ],
    },
]
  rules: [
    Rules {
        origin: Some(
            1,
        ),
        rules: [
            "query(1, 2) <- query(1), query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
        ],
    },
]
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if true trusting previous, ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
        ],
    },
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
            "check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
        ],
    },
    Checks {
        origin: Some(
            2,
        ),
        checks: [
            "check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
            "check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
        ],
    },
    Checks {
        origin: Some(
            3,
        ),
        checks: [
            "check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
            "check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
        ],
    },
    Checks {
        origin: Some(
            4,
        ),
        checks: [
            "check if query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
            "check if query(4) trusting ed25519/f98da8c1cf907856431bfc3dc87531e0eaadba90f919edc232405b85877ef136",
        ],
    },
    Checks {
        origin: Some(
            18446744073709551615,
        ),
        checks: [
            "check if query(1, 2) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189, ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
        ],
    },
]
  policies: [
    "deny if query(3)",
    "deny if query(1, 2)",
    "deny if query(0) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
    "allow if true",
]
}
```

result: `Ok(3)`


------------------------------

## integer wraparound: test027_integer_wraparound.bc
### token

authority:
symbols: []

public keys: []

block version: 4

```
check if 10000000000 * 10000000000 !== 0;
check if 9223372036854775807 + 1 !== 0;
check if -9223372036854775808 - 1 !== 0;
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `fb5e7ac2bb892f5cf2fb59677cfad1f96deabbc8e158e3fd1b5ee7c4b6949c999e2169187cbee53b943eebdadaaf68832747baa8cffa2ff9f78025a1f55f440c`

authorizer world:
```
World {
  facts: []
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if -9223372036854775808 - 1 !== 0",
            "check if 10000000000 * 10000000000 !== 0",
            "check if 9223372036854775807 + 1 !== 0",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(Execution(Overflow))`


------------------------------

## test expression syntax and all available operations (v4 blocks): test028_expressions_v4.bc
### token

authority:
symbols: ["abcD12x", "abcD12"]

public keys: []

block version: 4

```
check if 1 !== 3;
check if 1 | 2 ^ 3 === 0;
check if "abcD12x" !== "abcD12";
check if 2022-12-04T09:46:41Z !== 2020-12-04T09:46:41Z;
check if hex:12abcd !== hex:12ab;
check if {1, 4} !== {1, 2};
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `117fa653744c859561555e6a6f5990e3a8e7817f91b87aa6991b6d64297158b4e884c92d10f49f74c96069df722aa676839b72751ca9d1fe83a7025b591de00b`

authorizer world:
```
World {
  facts: []
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if \"abcD12x\" !== \"abcD12\"",
            "check if 1 !== 3",
            "check if 1 | 2 ^ 3 === 0",
            "check if 2022-12-04T09:46:41Z !== 2020-12-04T09:46:41Z",
            "check if hex:12abcd !== hex:12ab",
            "check if {1, 4} !== {1, 2}",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## test reject if: test029_reject_if.bc
### token

authority:
symbols: ["test"]

public keys: []

block version: 6

```
reject if test($test), $test;
```

### validation

authorizer code:
```
test(false);

allow if true;
```

revocation ids:
- `8d175329f7cf161f3cb5badc52f0e22e520956cdb565edbed963e9b047b20a314a7de1c9eba6b7bbf622636516ab3cc7f91572ae9461d3152825e0ece5127a0a`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "test(false)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "reject if test($test), $test",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`
### validation for "rejection"

authorizer code:
```
test(true);

allow if true;
```

revocation ids:
- `8d175329f7cf161f3cb5badc52f0e22e520956cdb565edbed963e9b047b20a314a7de1c9eba6b7bbf622636516ab3cc7f91572ae9461d3152825e0ece5127a0a`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "test(true)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "reject if test($test), $test",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "reject if test($test), $test" })] }))`


------------------------------

## test null: test030_null.bc
### token

authority:
symbols: ["fact", "value"]

public keys: []

block version: 6

```
check if fact(null, $value), $value == null;
reject if fact(null, $value), $value != null;
```

### validation

authorizer code:
```
fact(null, null);

allow if true;
```

revocation ids:
- `fe50d65706a5945c76569d1ff2be8ece24276857631e96efa05959f73bb4ea8c772945738a01da77a1661aef2b8233b4f4e49ae220f2c81fd0b8da59c212750b`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "fact(null, null)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if fact(null, $value), $value == null",
            "reject if fact(null, $value), $value != null",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`
### validation for "rejection1"

authorizer code:
```
fact(null, 1);

allow if true;
```

revocation ids:
- `fe50d65706a5945c76569d1ff2be8ece24276857631e96efa05959f73bb4ea8c772945738a01da77a1661aef2b8233b4f4e49ae220f2c81fd0b8da59c212750b`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "fact(null, 1)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if fact(null, $value), $value == null",
            "reject if fact(null, $value), $value != null",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if fact(null, $value), $value == null" }), Block(FailedBlockCheck { block_id: 0, check_id: 1, rule: "reject if fact(null, $value), $value != null" })] }))`
### validation for "rejection2"

authorizer code:
```
fact(null, true);

allow if true;
```

revocation ids:
- `fe50d65706a5945c76569d1ff2be8ece24276857631e96efa05959f73bb4ea8c772945738a01da77a1661aef2b8233b4f4e49ae220f2c81fd0b8da59c212750b`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "fact(null, true)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if fact(null, $value), $value == null",
            "reject if fact(null, $value), $value != null",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if fact(null, $value), $value == null" }), Block(FailedBlockCheck { block_id: 0, check_id: 1, rule: "reject if fact(null, $value), $value != null" })] }))`
### validation for "rejection3"

authorizer code:
```
fact(null, "abcd");

allow if true;
```

revocation ids:
- `fe50d65706a5945c76569d1ff2be8ece24276857631e96efa05959f73bb4ea8c772945738a01da77a1661aef2b8233b4f4e49ae220f2c81fd0b8da59c212750b`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "fact(null, \"abcd\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if fact(null, $value), $value == null",
            "reject if fact(null, $value), $value != null",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if fact(null, $value), $value == null" }), Block(FailedBlockCheck { block_id: 0, check_id: 1, rule: "reject if fact(null, $value), $value != null" })] }))`


------------------------------

## test heterogeneous equal: test031_heterogeneous_equal.bc
### token

authority:
symbols: ["abcD12", "abcD12x", "fact", "value", "fact2"]

public keys: []

block version: 6

```
check if true == true;
check if false == false;
check if false != true;
check if 1 != true;
check if 1 == 1;
check if 1 != 3;
check if 1 != true;
check if "abcD12" == "abcD12";
check if "abcD12x" != "abcD12";
check if "abcD12x" != true;
check if 2022-12-04T09:46:41Z == 2022-12-04T09:46:41Z;
check if 2022-12-04T09:46:41Z != 2020-12-04T09:46:41Z;
check if 2022-12-04T09:46:41Z != true;
check if hex:12abcd == hex:12abcd;
check if hex:12abcd != hex:12ab;
check if hex:12abcd != true;
check if {1, 2} == {1, 2};
check if {1, 4} != {1, 2};
check if {1, 4} != true;
check if fact(1, $value), 1 == $value;
check if fact2(1, $value), 1 != $value;
```

### validation

authorizer code:
```
fact(1, 1);
fact2(1, 2);

allow if true;
```

revocation ids:
- `be50b2040f4b5fe278b87815910d249eeb9ca5238cae4ea538e22afda11f576e868cbfe7e6b0a03b02ae0f22239ec908947d4bad5a878e4b9f7bd7de73e5c90a`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "fact(1, 1)",
            "fact2(1, 2)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if \"abcD12\" == \"abcD12\"",
            "check if \"abcD12x\" != \"abcD12\"",
            "check if \"abcD12x\" != true",
            "check if 1 != 3",
            "check if 1 != true",
            "check if 1 != true",
            "check if 1 == 1",
            "check if 2022-12-04T09:46:41Z != 2020-12-04T09:46:41Z",
            "check if 2022-12-04T09:46:41Z != true",
            "check if 2022-12-04T09:46:41Z == 2022-12-04T09:46:41Z",
            "check if fact(1, $value), 1 == $value",
            "check if fact2(1, $value), 1 != $value",
            "check if false != true",
            "check if false == false",
            "check if hex:12abcd != hex:12ab",
            "check if hex:12abcd != true",
            "check if hex:12abcd == hex:12abcd",
            "check if true == true",
            "check if {1, 2} == {1, 2}",
            "check if {1, 4} != true",
            "check if {1, 4} != {1, 2}",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`
### validation for "evaluate to false"

authorizer code:
```
fact(1, 2);
fact2(1, 1);

check if false != false;

allow if true;
```

revocation ids:
- `be50b2040f4b5fe278b87815910d249eeb9ca5238cae4ea538e22afda11f576e868cbfe7e6b0a03b02ae0f22239ec908947d4bad5a878e4b9f7bd7de73e5c90a`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "fact(1, 2)",
            "fact2(1, 1)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if \"abcD12\" == \"abcD12\"",
            "check if \"abcD12x\" != \"abcD12\"",
            "check if \"abcD12x\" != true",
            "check if 1 != 3",
            "check if 1 != true",
            "check if 1 != true",
            "check if 1 == 1",
            "check if 2022-12-04T09:46:41Z != 2020-12-04T09:46:41Z",
            "check if 2022-12-04T09:46:41Z != true",
            "check if 2022-12-04T09:46:41Z == 2022-12-04T09:46:41Z",
            "check if fact(1, $value), 1 == $value",
            "check if fact2(1, $value), 1 != $value",
            "check if false != true",
            "check if false == false",
            "check if hex:12abcd != hex:12ab",
            "check if hex:12abcd != true",
            "check if hex:12abcd == hex:12abcd",
            "check if true == true",
            "check if {1, 2} == {1, 2}",
            "check if {1, 4} != true",
            "check if {1, 4} != {1, 2}",
        ],
    },
    Checks {
        origin: Some(
            18446744073709551615,
        ),
        checks: [
            "check if false != false",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Authorizer(FailedAuthorizerCheck { check_id: 0, rule: "check if false != false" }), Block(FailedBlockCheck { block_id: 0, check_id: 19, rule: "check if fact(1, $value), 1 == $value" }), Block(FailedBlockCheck { block_id: 0, check_id: 20, rule: "check if fact2(1, $value), 1 != $value" })] }))`


------------------------------

## test laziness and closures: test032_laziness_closures.bc
### token

authority:
symbols: ["x", "p", "q"]

public keys: []

block version: 6

```
check if !false && true;
check if false || true;
check if (true || false) && true;
check if !(false && "x".intersection("x"));
check if true || "x".intersection("x");
check if {1, 2, 3}.all($p -> $p > 0);
check if !{1, 2, 3}.all($p -> $p == 2);
check if {1, 2, 3}.any($p -> $p > 2);
check if !{1, 2, 3}.any($p -> $p > 3);
check if {1, 2, 3}.any($p -> $p > 1 && {3, 4, 5}.any($q -> $p == $q));
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `2cd348b6df5f08b900903fd8d3fbea0bb89b665c331a2aa2131e0b8ecb38b3550275d4ccd8db35da6c4433eed1d456cfb761e3fcc7845894d891e986ca044b02`

authorizer world:
```
World {
  facts: []
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if !(false && \"x\".intersection(\"x\"))",
            "check if !false && true",
            "check if !{1, 2, 3}.all($p -> $p == 2)",
            "check if !{1, 2, 3}.any($p -> $p > 3)",
            "check if (true || false) && true",
            "check if false || true",
            "check if true || \"x\".intersection(\"x\")",
            "check if {1, 2, 3}.all($p -> $p > 0)",
            "check if {1, 2, 3}.any($p -> $p > 1 && {3, 4, 5}.any($q -> $p == $q))",
            "check if {1, 2, 3}.any($p -> $p > 2)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`
### validation for "shadowing"

authorizer code:
```
allow if [true].any($p -> [true].all($p -> $p));
```

revocation ids:
- `2cd348b6df5f08b900903fd8d3fbea0bb89b665c331a2aa2131e0b8ecb38b3550275d4ccd8db35da6c4433eed1d456cfb761e3fcc7845894d891e986ca044b02`

authorizer world:
```
World {
  facts: []
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if !(false && \"x\".intersection(\"x\"))",
            "check if !false && true",
            "check if !{1, 2, 3}.all($p -> $p == 2)",
            "check if !{1, 2, 3}.any($p -> $p > 3)",
            "check if (true || false) && true",
            "check if false || true",
            "check if true || \"x\".intersection(\"x\")",
            "check if {1, 2, 3}.all($p -> $p > 0)",
            "check if {1, 2, 3}.any($p -> $p > 1 && {3, 4, 5}.any($q -> $p == $q))",
            "check if {1, 2, 3}.any($p -> $p > 2)",
        ],
    },
]
  policies: [
    "allow if [true].any($p -> [true].all($p -> $p))",
]
}
```

result: `Err(Execution(ShadowedVariable))`


------------------------------

## test .type(): test033_typeof.bc
### token

authority:
symbols: ["integer", "string", "test", "date", "bytes", "bool", "set", "null", "array", "map", "a", "t"]

public keys: []

block version: 6

```
integer(1);
string("test");
date(2023-12-28T00:00:00Z);
bytes(hex:aa);
bool(true);
set({false, true});
null(null);
array([1, 2, 3]);
map({"a": true});
check if 1.type() == "integer";
check if integer($t), $t.type() == "integer";
check if "test".type() == "string";
check if string($t), $t.type() == "string";
check if (2023-12-28T00:00:00Z).type() == "date";
check if date($t), $t.type() == "date";
check if hex:aa.type() == "bytes";
check if bytes($t), $t.type() == "bytes";
check if true.type() == "bool";
check if bool($t), $t.type() == "bool";
check if {false, true}.type() == "set";
check if set($t), $t.type() == "set";
check if null.type() == "null";
check if null($t), $t.type() == "null";
check if array($t), $t.type() == "array";
check if map($t), $t.type() == "map";
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `e60875c6ef7917c227a5e4b2cabfe250a85fa0598eb3cf7987ded0da2b69a559a1665bd312aeecde78e76aeb28ea1c1a03ec9b7dec8aeb519e7867ef8ff9b402`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "array([1, 2, 3])",
            "bool(true)",
            "bytes(hex:aa)",
            "date(2023-12-28T00:00:00Z)",
            "integer(1)",
            "map({\"a\": true})",
            "null(null)",
            "set({false, true})",
            "string(\"test\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if \"test\".type() == \"string\"",
            "check if (2023-12-28T00:00:00Z).type() == \"date\"",
            "check if 1.type() == \"integer\"",
            "check if array($t), $t.type() == \"array\"",
            "check if bool($t), $t.type() == \"bool\"",
            "check if bytes($t), $t.type() == \"bytes\"",
            "check if date($t), $t.type() == \"date\"",
            "check if hex:aa.type() == \"bytes\"",
            "check if integer($t), $t.type() == \"integer\"",
            "check if map($t), $t.type() == \"map\"",
            "check if null($t), $t.type() == \"null\"",
            "check if null.type() == \"null\"",
            "check if set($t), $t.type() == \"set\"",
            "check if string($t), $t.type() == \"string\"",
            "check if true.type() == \"bool\"",
            "check if {false, true}.type() == \"set\"",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## test array and map operations: test034_array_map.bc
### token

authority:
symbols: ["a", "b", "c", "p", "d", "A", "kv", "id", "roles"]

public keys: []

block version: 6

```
check if [1, 2, 1].length() == 3;
check if ["a", "b"] != true;
check if ["a", "b"] != [1, 2, 3];
check if ["a", "b"] == ["a", "b"];
check if ["a", "b"] === ["a", "b"];
check if ["a", "b"] !== ["a", "c"];
check if ["a", "b", "c"].contains("c");
check if [1, 2, 3].starts_with([1, 2]);
check if [4, 5, 6].ends_with([6]);
check if [1, 2, "a"].get(2) == "a";
check if [1, 2].get(3) == null;
check if [1, 2, 3].all($p -> $p > 0);
check if [1, 2, 3].any($p -> $p > 2);
check if {"a": 1, "b": 2, "c": 3, "d": 4}.length() == 4;
check if {1: "a", 2: "b"} != true;
check if {1: "a", 2: "b"} != {"a": 1, "b": 2};
check if {1: "a", 2: "b"} == {1: "a", 2: "b"};
check if {1: "a", 2: "b"} !== {"a": 1, "b": 2};
check if {1: "a", 2: "b"} === {1: "a", 2: "b"};
check if {"a": 1, "b": 2, "c": 3, "d": 4}.contains("d");
check if {1: "A", "a": 1, "b": 2}.get("a") == 1;
check if {1: "A", "a": 1, "b": 2}.get(1) == "A";
check if {1: "A", "a": 1, "b": 2}.get("c") == null;
check if {1: "A", "a": 1, "b": 2}.get(2) == null;
check if {"a": 1, "b": 2}.all($kv -> $kv.get(0) != "c" && $kv.get(1) < 3);
check if {1: "A", "a": 1, "b": 2}.any($kv -> $kv.get(0) == 1 && $kv.get(1) == "A");
check if {"user": {"id": 1, "roles": ["admin"]}}.get("user").get("roles").contains("admin");
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `b22238a06ca9c015d3c49d4ebaa7e8ab6e0d69119b3264033618e726d62fc6f4757a7bebc25f255444aba39994554a62a53ecc13b68802efab8da85ace62390d`

authorizer world:
```
World {
  facts: []
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if [\"a\", \"b\", \"c\"].contains(\"c\")",
            "check if [\"a\", \"b\"] != [1, 2, 3]",
            "check if [\"a\", \"b\"] != true",
            "check if [\"a\", \"b\"] !== [\"a\", \"c\"]",
            "check if [\"a\", \"b\"] == [\"a\", \"b\"]",
            "check if [\"a\", \"b\"] === [\"a\", \"b\"]",
            "check if [1, 2, \"a\"].get(2) == \"a\"",
            "check if [1, 2, 1].length() == 3",
            "check if [1, 2, 3].all($p -> $p > 0)",
            "check if [1, 2, 3].any($p -> $p > 2)",
            "check if [1, 2, 3].starts_with([1, 2])",
            "check if [1, 2].get(3) == null",
            "check if [4, 5, 6].ends_with([6])",
            "check if {\"a\": 1, \"b\": 2, \"c\": 3, \"d\": 4}.contains(\"d\")",
            "check if {\"a\": 1, \"b\": 2, \"c\": 3, \"d\": 4}.length() == 4",
            "check if {\"a\": 1, \"b\": 2}.all($kv -> $kv.get(0) != \"c\" && $kv.get(1) < 3)",
            "check if {\"user\": {\"id\": 1, \"roles\": [\"admin\"]}}.get(\"user\").get(\"roles\").contains(\"admin\")",
            "check if {1: \"A\", \"a\": 1, \"b\": 2}.any($kv -> $kv.get(0) == 1 && $kv.get(1) == \"A\")",
            "check if {1: \"A\", \"a\": 1, \"b\": 2}.get(\"a\") == 1",
            "check if {1: \"A\", \"a\": 1, \"b\": 2}.get(\"c\") == null",
            "check if {1: \"A\", \"a\": 1, \"b\": 2}.get(1) == \"A\"",
            "check if {1: \"A\", \"a\": 1, \"b\": 2}.get(2) == null",
            "check if {1: \"a\", 2: \"b\"} != true",
            "check if {1: \"a\", 2: \"b\"} != {\"a\": 1, \"b\": 2}",
            "check if {1: \"a\", 2: \"b\"} !== {\"a\": 1, \"b\": 2}",
            "check if {1: \"a\", 2: \"b\"} == {1: \"a\", 2: \"b\"}",
            "check if {1: \"a\", 2: \"b\"} === {1: \"a\", 2: \"b\"}",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## test ffi calls (v6 blocks): test035_ffi.bc
### token

authority:
symbols: ["test", "a", "equal strings"]

public keys: []

block version: 6

```
check if true.extern::test(), "a".extern::test("a") == "equal strings";
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `d1719fd101c2695d2dac4df67569918363f691b6167670e1dbbf8026f639a7aa1ec2e13707f4d34cadbb2adce5c6e8a816577dd069a8717e0f5cb4ea3cec5b04`

authorizer world:
```
World {
  facts: []
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if true.extern::test(), \"a\".extern::test(\"a\") == \"equal strings\"",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## ECDSA secp256r1 signatures: test036_secp256r1.bc
### token

authority:
symbols: ["file1", "file2"]

public keys: []

block version: 3

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["0"]

public keys: []

block version: 3

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

authorizer code:
```
resource("file1");
operation("read");

allow if true;
```

revocation ids:
- `628b9a6d74cc80b3ece50befd1f5f0f025c0a35d51708b2e77c11aed5f968b93b4096c87ed8169605716de934e155443f140334d71708fcc4247e5a0a518b30d`
- `3046022100b60674854a12814cc36c8aab9600c1d9f9d3160e2334b72c0feede5a56213ea5022100a4f4bbf2dc33b309267af39fce76612017ddb6171e9cd2a3aa8a853f45f1675f`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file1\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"file1\", \"read\")",
            "right(\"file1\", \"write\")",
            "right(\"file2\", \"read\")",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if resource($0), operation(\"read\"), right($0, \"read\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## ECDSA secp256r1 signature on third-party block: test037_secp256r1_third_party.bc
### token

authority:
symbols: ["file1", "file2", "from_third"]

public keys: ["secp256r1/025e918fd4463832aea2823dfd9716a36b4d9b1377bd53dd82ddf4c0bc75ed6bbf"]

block version: 4

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
check if from_third(true) trusting secp256r1/025e918fd4463832aea2823dfd9716a36b4d9b1377bd53dd82ddf4c0bc75ed6bbf;
```

1:
symbols: ["from_third", "0"]

public keys: []

external signature by: "secp256r1/025e918fd4463832aea2823dfd9716a36b4d9b1377bd53dd82ddf4c0bc75ed6bbf"

block version: 5

```
from_third(true);
check if resource($0), operation("read"), right($0, "read");
```

### validation

authorizer code:
```
resource("file1");
operation("read");

allow if true;
```

revocation ids:
- `70f5402208516fd44cfc9df3dfcfc0a327ee9004f1801ed0a7abdcbbae923d566ddcd2d4a14f4622b35732c4e538af04075cc67ab0888fa2d8923cc668187f0f`
- `30450220793f95665d9af646339503a073670ea2c352459d2a2c2e14c57565f6c7eaf6bc022100cccadfc37e46755f52bb054ed206d7335067885df599a69431db40e33f33d4cf`

authorizer world:
```
World {
  facts: [
    Facts {
        origin: {
            None,
        },
        facts: [
            "operation(\"read\")",
            "resource(\"file1\")",
        ],
    },
    Facts {
        origin: {
            Some(
                0,
            ),
        },
        facts: [
            "right(\"file1\", \"read\")",
            "right(\"file1\", \"write\")",
            "right(\"file2\", \"read\")",
        ],
    },
    Facts {
        origin: {
            Some(
                1,
            ),
        },
        facts: [
            "from_third(true)",
        ],
    },
]
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if from_third(true) trusting secp256r1/025e918fd4463832aea2823dfd9716a36b4d9b1377bd53dd82ddf4c0bc75ed6bbf",
        ],
    },
    Checks {
        origin: Some(
            1,
        ),
        checks: [
            "check if resource($0), operation(\"read\"), right($0, \"read\")",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`


------------------------------

## test try operation: test038_try_op.bc
### token

authority:
symbols: []

public keys: []

block version: 6

```
check if (true === 12).try_or(true);
check if ((true === 12).try_or(true === 12)).try_or(true);
reject if (true == 12).try_or(true);
```

### validation

authorizer code:
```
allow if true;
```

revocation ids:
- `79674155cd5349604e89b00792aeaebfa0a512bd45edc289305ebec107f627d3d8c09847646a0d06c2390a4354771b2ebdc2cc66971f2d74ef744e4e81197600`

authorizer world:
```
World {
  facts: []
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if ((true === 12).try_or(true === 12)).try_or(true)",
            "check if (true === 12).try_or(true)",
            "reject if (true == 12).try_or(true)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Ok(0)`
### validation for "right-hand side does not catch errors"

authorizer code:
```
check if true.try_or(true === 12);

allow if true;
```

revocation ids:
- `79674155cd5349604e89b00792aeaebfa0a512bd45edc289305ebec107f627d3d8c09847646a0d06c2390a4354771b2ebdc2cc66971f2d74ef744e4e81197600`

authorizer world:
```
World {
  facts: []
  rules: []
  checks: [
    Checks {
        origin: Some(
            0,
        ),
        checks: [
            "check if ((true === 12).try_or(true === 12)).try_or(true)",
            "check if (true === 12).try_or(true)",
            "reject if (true == 12).try_or(true)",
        ],
    },
    Checks {
        origin: Some(
            18446744073709551615,
        ),
        checks: [
            "check if true.try_or(true === 12)",
        ],
    },
]
  policies: [
    "allow if true",
]
}
```

result: `Err(Execution(InvalidType))`

