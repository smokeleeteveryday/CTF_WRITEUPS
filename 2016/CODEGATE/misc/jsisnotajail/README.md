# CODEGATE 2016: JS_is_not_a_jail

## Challenge details
| Event | Challenge | Category | Points |
|:------|:----------|:---------|-------:|
| CODEGATE | JS_is_not_a_jail | Misc. | 100 |

### Description
> nc 175.119.158.131 1129

## Write-up

This challenge dropped us into a JavaScript Jail which held a function which we had to trick into giving us the flag. We start by checking out what is available to us:

```javascript
$ nc 175.119.158.131 1129
[JavaScript Jail]
let start to type on 'challenge100'
V8 version 5.1.0 (candidate)
d8> print(Object.keys(this));
print(Object.keys(this));
print,write,read,readbuffer,readline,load,quit,version,Realm,performance,Worker,os,arguments,js_challenge,challenge100
undefined

print(challenge100);

d8> print(challenge100);
print(challenge100);
function (arr) {
        var random_value = "ac1a39300ce7ee8b6cff8021fd7b0b5caf5bc1c316697bd8f22e00f9fab710d6b8dba23ca80f6d80ca697e7aa26fd5f6";
        var check = "20150303";

        if((arr === null || arr === undefined)) {
            print("arr is null or undefined.");
            return;
        }

        if(!arr.hasOwnProperty('length')) {
            print("length property is null or undefined.");
            return;
        }

        if(arr.length >= 0) {
            print("i think you're not geek. From now on, a GEEK Only!");
            return;
        }

        if(Object.getPrototypeOf(arr) !== Array.prototype) {
            print("Oh.... can you give me an array?");
            return;
        }

        var length = check.length;
        for(var i=0;i<length;i++) {
            arr[i] = random_value[Math.floor(Math.random() * random_value.length)];
        }

        for(i=0;i<length;i++) {
            if(arr[i] !== check[i]) {
                print("Umm... i think 2015/03/03 is so special day.\nso you must set random value to 20150303 :)");
                return;
            }
        }
        print("Yay!!");
        print(flag);
    }
undefined
```

There is not really a genuine way to craft input that matches the constraints of the `challenge100` function so we have to (re)define values and objects to trick it. Luckily this is JavaScript so we can do pretty much anything.

Let's get rid of the first two checks:

```javascript
Object.getPrototypeOf = function() {return Array.prototype;};
var arr = {length: -1};
```

Now we need to make sure `arr` is set to:

```javascript
arr[0] = '2';
arr[1] = '0';
arr[2] = '1';
arr[3] = '5';
arr[4] = '0';
arr[5] = '3';
arr[6] = '0';
arr[7] = '3';
```

Since `arr` is assigned by values drawn from random_value using (Math.floor(Math.random() * random_value.length)) we need to redefine `Math.floor` and `Math.random` to produce the sequence `{22, 7, 2, 30, 7, 4, 7, 4}` which, when treated as indexes into `random_value` will set `arr` to the right values. We do this by first defining a global:

```javascript
var steps = [22, 7, 2, 30, 7, 4, 7, 4];
var stepindex = 0;
```

And redefining `Math.random` and `Math.floor` as:

```javascript
Math.random = function() {var r = steps[stepindex]; stepindex = (stepindex + 1); return r;};
Math.floor = function(i) {return (i / 96);}
```

Which gives us:

```bash
$ nc 175.119.158.131 1129
[JavaScript Jail]
let start to type on 'challenge100'
V8 version 5.1.0 (candidate)
d8> Object.getPrototypeOf = function() {return Array.prototype;};
d8> var arr = {length: -1};
undefined
d8> var steps = [22, 7, 2, 30, 7, 4, 7, 4];
undefined
d8> var stepindex = 0;
undefined
d8> Math.random = function() {var r = steps[stepindex]; stepindex = (stepindex + 1); return r;};
function () {var r = steps[stepindex]; stepindex = (stepindex + 1); return r;}
d8> Math.floor = function(i) {return (i / 96);}
function (i) {return (i / 96);}
d8> challenge100(arr);
challenge100(arr);challenge100(arr);
Yay!!
flag is "easy xD, get a more hardest challenge!"
```