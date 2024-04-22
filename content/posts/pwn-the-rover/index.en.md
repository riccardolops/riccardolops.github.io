---
weight: 4
title: "PWN THE ROVER"
date: 2023-09-21T19:02:26+02:00
lastmod: 2023-09-28T15:08:50+02:00
draft: false
description: "This article shows the solutions for the PTR qualification contest."
images: []
resources:
- name: "featured-image"
  src: "featured-image.png"

tags: ["Space", "Cybersecurity"]
categories: ["Blog"]

lightgallery: true
---

# pwn-the-rover: ESA Hacking Contest

Two of the things that fascinate me most are space exploration and cybersecurity. So, when my university secretary forwarded me an email about a hacking contest from ESA this Monday, I decided to give it a shot.
<!--more-->
The contest in question is ["PWN THE ROVER"](https://pwn-the-rover.space), and to participate in the event, you need to solve a set of capture the flag qualification challenges. Like any respectable CTF, to complete the challenge, you need to find tokens in this format: `PTR{challenge-dependent-token}`. They can be solved independently from one another. If you want to try to solve them yourself, you can find the archive [:(far fa-file-archive fa-fw): here](qualification-challenges.zip).

Unfortunately, they are not going to publish the solutions, so I decided to share in this blog post how I solved four of the five challenges (I was not able to finish the second one 😕, but if I crack it, I will update the post).

{{< admonition info "Info" true >}}
I won't go into details about steganography or reverse engineering but only tell how I arrived at the solutions.
{{< /admonition >}}

## 1. haveALook


![challenge.jpg](challenge.jpg "challenge.jpg")

The first challenge starts with... a rick-roll 🤣. A single JPEG file with a QR code is given, but upon scanning it, you can see that the URL presents a fragment identifier:

`https://www.youtube.com/watch?v=dQw4w9WgXcQ#PrinceProcessorCanHelpWithTheTitle`

The only hint here is about [princeprocessor](https://github.com/hashcat/princeprocessor), a clever tool that helps you generate password dictionaries.
First I created a file with the title:

{{< asciinema RrVmlkIWoUoMfHenyzrnVnBAy >}}

Then I used princeprocessor to generate a dictionary:

{{< asciinema emQerMk55ybqAfKBgThdwLMTK >}}

At this point, I was not sure on what to do, so I thought maybe there was something else hidden in the image, perhaps through [steghide](https://steghide.sourceforge.net/).

To brute force the possible solutions, I used a simple Python [script](https://github.com/Paradoxis/StegCracker) but later discovered a faster alternative called [stegseek](https://github.com/RickdeJager/stegseek) that basically does the same thing:

{{< asciinema pJmpYxKKnuad9PRvQY8MQjwLF >}}

BINGO!!! The first flag is done! `PTR{R1ckR0ll&St3ganogr4phyComb0}`

## 2. missingChat

![Screenshot_20230808-pixel6pro.png](Screenshot_20230808-pixel6pro.png "Screenshot_20230808-pixel6pro.png")

For this one, I don't have the solution, but I noticed that the PNG has some extra data after the IEND chunk, with as far as I understand, some other IDAT chunks.

{{< asciinema EngGkESslXOcZPGttmX08rJ9v >}}

This has led me to believe that most likely they hid the rest of the "missing chat" image with the token at the end of the file.

Nothing much to say here, unfortunately 😕.

### Update!!!

After some googling I found a vulnerability that affected a screenshot editing tool in Google Pixel phones: [aCropalypse (CVE 2023-21036)](https://en.wikipedia.org/wiki/ACropalypse).

Online you can find [tools](https://acropalypse.app) that will restore the screenshot and from that I was able to get `PTR{Rolling-Stones4}`
![acropalypse.png](acropalypse.png "acropalypse.png")

## 3. androidTrivial

The next three challenges are more or less the same, only with increasing difficulty 😄.

There is a lot of info on the internet on reverse engineering on Android, but I found [this guide](https://github.com/OWASP/owasp-mastg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md) very useful.

For the first Android app, it was pretty straightforward to discover the password since it was not obfuscated at all in the source code obtained after decompilation with an online [decompiler](http://www.javadecompilers.com/apk/).


```java
package org.esa.ptr23.qualification;

import android.content.Context;
import org.esa.ptr23.qualification.trivial.R;

public class Verifier {
    private Verifier() {
    }

    public static boolean verifyPassword(Context context, String str) {
        return context.getString(R.string.something_hidden).equals(str.trim());
    }
}
```
This is the Verifier class with a simple function that checks if the input string `str.trim()` is equal to `something_hidden`
```xml
    <string name="something_hidden">PTR{SpaceMayBeTheFinalFrontier}</string>
```

## 4. androidEasy

Here, the same class has a hashmap that associates each alphabet letter with an emoji.

```java
package org.esa.ptr23.qualification;

import android.content.Context;
import java.util.HashMap;
import java.util.Map;

public class Verifier {
    private Map<Character, changeChar> translate;

    private interface changeChar {
        String change(String str);
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$a */
    private class C0464a implements changeChar {
        public String change(String str) {
            return "😸";
        }

        private C0464a() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$c */
    private class C0466c implements changeChar {
        public String change(String str) {
            return "😹";
        }

        private C0466c() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$b */
    private class C0465b implements changeChar {
        public String change(String str) {
            return "🐱";
        }

        private C0465b() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$e */
    private class C0468e implements changeChar {
        public String change(String str) {
            return "😻";
        }

        private C0468e() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$d */
    private class C0467d implements changeChar {
        public String change(String str) {
            return "😺";
        }

        private C0467d() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$g */
    private class C0470g implements changeChar {
        public String change(String str) {
            return "😽";
        }

        private C0470g() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$f */
    private class C0469f implements changeChar {
        public String change(String str) {
            return "😼";
        }

        private C0469f() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$i */
    private class C0472i implements changeChar {
        public String change(String str) {
            return "😿";
        }

        private C0472i() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$h */
    private class C0471h implements changeChar {
        public String change(String str) {
            return "😾";
        }

        private C0471h() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$k */
    private class C0474k implements changeChar {
        public String change(String str) {
            return "🐆";
        }

        private C0474k() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$j */
    private class C0473j implements changeChar {
        public String change(String str) {
            return "🙀";
        }

        private C0473j() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$m */
    private class C0476m implements changeChar {
        public String change(String str) {
            return "🦍";
        }

        private C0476m() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$l */
    private class C0475l implements changeChar {
        public String change(String str) {
            return "🐅";
        }

        private C0475l() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$o */
    private class C0478o implements changeChar {
        public String change(String str) {
            return "🦑";
        }

        private C0478o() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$n */
    private class C0477n implements changeChar {
        public String change(String str) {
            return "🐍";
        }

        private C0477n() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$q */
    private class C0480q implements changeChar {
        public String change(String str) {
            return "🐊";
        }

        private C0480q() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$p */
    private class C0479p implements changeChar {
        public String change(String str) {
            return "🐌";
        }

        private C0479p() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$s */
    private class C0482s implements changeChar {
        public String change(String str) {
            return "🙈";
        }

        private C0482s() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$r */
    private class C0481r implements changeChar {
        public String change(String str) {
            return "🦎";
        }

        private C0481r() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$u */
    private class C0484u implements changeChar {
        public String change(String str) {
            return "🎮";
        }

        private C0484u() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$t */
    private class C0483t implements changeChar {
        public String change(String str) {
            return "🦗";
        }

        private C0483t() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$w */
    private class C0486w implements changeChar {
        public String change(String str) {
            return "℡";
        }

        private C0486w() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$v */
    private class C0485v implements changeChar {
        public String change(String str) {
            return "🎛";
        }

        private C0485v() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$y */
    private class C0488y implements changeChar {
        public String change(String str) {
            return "🖪";
        }

        private C0488y() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$x */
    private class C0487x implements changeChar {
        public String change(String str) {
            return "💿";
        }

        private C0487x() {
        }
    }

    /* renamed from: org.esa.ptr23.qualification.Verifier$z */
    private class C0489z implements changeChar {
        public String change(String str) {
            return "🎥";
        }

        private C0489z() {
        }
    }

    private class curlybracketopen implements changeChar {
        public String change(String str) {
            return "🦈";
        }

        private curlybracketopen() {
        }
    }

    private class curlybracketclose implements changeChar {
        public String change(String str) {
            return "🧸";
        }

        private curlybracketclose() {
        }
    }

    private class unchanged implements changeChar {
        public String change(String str) {
            return str;
        }

        private unchanged() {
        }
    }

    private Verifier() {
        HashMap hashMap = new HashMap();
        this.translate = hashMap;
        hashMap.put('a', new C0464a());
        this.translate.put('b', new C0465b());
        this.translate.put('c', new C0466c());
        this.translate.put('d', new C0467d());
        this.translate.put('e', new C0468e());
        this.translate.put('f', new C0469f());
        this.translate.put('g', new C0470g());
        this.translate.put('h', new C0471h());
        this.translate.put('i', new C0472i());
        this.translate.put('j', new C0473j());
        this.translate.put('k', new C0474k());
        this.translate.put('l', new C0475l());
        this.translate.put('m', new C0476m());
        this.translate.put('n', new C0477n());
        this.translate.put('o', new C0478o());
        this.translate.put('p', new C0479p());
        this.translate.put('q', new C0480q());
        this.translate.put('r', new C0481r());
        this.translate.put('s', new C0482s());
        this.translate.put('t', new C0483t());
        this.translate.put('u', new C0484u());
        this.translate.put('v', new C0485v());
        this.translate.put('w', new C0486w());
        this.translate.put('x', new C0487x());
        this.translate.put('y', new C0488y());
        this.translate.put('z', new C0489z());
        this.translate.put('{', new curlybracketopen());
        this.translate.put('}', new curlybracketclose());
    }

    private String doit(String str) {
        StringBuilder sb = new StringBuilder();
        char[] charArray = str.toCharArray();
        int length = charArray.length;
        int i = 0;
        while (i < length) {
            char c = charArray[i];
            try {
                sb.append(this.translate.get(Character.valueOf(c)).change(String.valueOf(c)));
                i++;
            } catch (NullPointerException unused) {
                return "";
            }
        }
        return sb.toString().trim();
    }

    public static boolean verifyPassword(Context context, String str) {
        return new Verifier().doit(str.toLowerCase()).equals("🐌🦗🦎🦈😿🦍😸😽😿🐍😻🦗😾😻🦎😻🙈🐍🦑😾😻😸🎛😻🐍🧸");
    }
}
```
So in the end `🐌🦗🦎🦈😿🦍😸😽😿🐍😻🦗😾😻🦎😻🙈🐍🦑😾😻😸🎛😻🐍🧸` becomes `PTR{ImagineTheresNoHeaven}`


## 5. androidIntermediate

The last one has a class that uses a Java Native Interface (JNI) method called `checkPasswordByJNI07` loaded by the library `native-lib`

```java
package org.esa.ptr23.qualification;

import android.content.Context;

public class Verifier {
    private static final String TAG = "Verifier";

    public static native String checkPasswordByJNI07(String str);

    static {
        System.loadLibrary("native-lib");
    }

    private Verifier() {
    }

    public static boolean verifyPassword(Context context, String str) {
        return "TRUE".equals(checkPasswordByJNI07(str));
    }
}
```

The logical next step was to reverse-engineer the pre-built native library using [Ghidra](https://ghidra-sre.org/)

```cpp

jstring Java_org_esa_ptr23_qualification_Verifier_checkPasswordByJNI07
                  (JNIEnv *param_1,undefined8 param_2,jstring param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  char *chars;
  char *pcVar5;
  int *__ptr;
  jstring p_Var6;
  char *pcVar7;
  size_t *psVar8;
  char **ppcVar9;
  size_t __n;
  long in_FS_OFFSET;
  undefined8 local_50;
  size_t local_48;
  char *local_40;
  long local_38;
  jsize jVar4;
  
  local_38 = *(long *)(in_FS_OFFSET + 0x28);
  jVar4 = (*(*param_1)->GetStringUTFLength)(param_1,param_3);
  uVar3 = (uint)jVar4;
  chars = (*(*param_1)->GetStringUTFChars)(param_1,param_3,(jboolean *)0x0);
  if (0xffffffef < uVar3) {
    std::__ndk1::__basic_string_common<true>::__throw_length_error();
    goto LAB_00123d03;
  }
  __n = (size_t)(int)uVar3;
  if (uVar3 < 0x17) {
    local_50 = CONCAT71(local_50._1_7_,(char)jVar4 * '\x02');
    pcVar5 = (char *)((long)&local_50 + 1);
    if (uVar3 != 0) goto LAB_00123976;
  }
  else {
    local_50 = __n + 0x10 & 0xfffffffffffffff0;
    pcVar5 = (char *)operator.new(local_50);
    local_50 = local_50 | 1;
    local_48 = __n;
    local_40 = pcVar5;
LAB_00123976:
    memcpy(pcVar5,chars,__n);
  }
  pcVar5[__n] = '\0';
  __ptr = (int *)malloc(0x4c);
  *__ptr = 0x50;
  __ptr[1] = 0x55;
  __ptr[2] = 0x54;
  __ptr[3] = 0x7e;
  __ptr[4] = 0x4a;
  __ptr[5] = 0x71;
  __ptr[6] = 0x7f;
  __ptr[7] = 0x54;
  __ptr[8] = 0x6d;
  __ptr[9] = 0x5d;
  __ptr[10] = 0x79;
  __ptr[0xb] = 0x5f;
  __ptr[0xc] = 0x74;
  __ptr[0xd] = 0x72;
  __ptr[0xe] = 0x5b;
  __ptr[0xf] = 0x7e;
  *(undefined8 *)(__ptr + 0x10) = 0x7f0000007f;
  __ptr[0x12] = 0x8f;
                    /* try { // try from 001239dd to 001239ec has its CatchHandler @ 00123d0a */
  p_Var6 = (*(*param_1)->NewStringUTF)(param_1,"FALSE");
  if (uVar3 == 0x13) {
    pcVar5 = (char *)((long)&local_50 + 1);
    pcVar7 = local_40;
    if ((local_50 & 1) == 0) {
      pcVar7 = pcVar5;
    }
    if (*__ptr == (int)*pcVar7) {
      pcVar7 = local_40;
      if ((local_50 & 1) == 0) {
        pcVar7 = pcVar5;
      }
      if (__ptr[1] == pcVar7[1] + 1) {
        pcVar7 = local_40;
        if ((local_50 & 1) == 0) {
          pcVar7 = pcVar5;
        }
        if (__ptr[2] == pcVar7[2] + 2) {
          pcVar7 = local_40;
          if ((local_50 & 1) == 0) {
            pcVar7 = pcVar5;
          }
          if (__ptr[3] == pcVar7[3] + 3) {
            pcVar7 = local_40;
            if ((local_50 & 1) == 0) {
              pcVar7 = pcVar5;
            }
            if (__ptr[4] == pcVar7[4] + 4) {
              pcVar7 = local_40;
              if ((local_50 & 1) == 0) {
                pcVar7 = pcVar5;
              }
              if (__ptr[5] == pcVar7[5] + 5) {
                pcVar7 = local_40;
                if ((local_50 & 1) == 0) {
                  pcVar7 = pcVar5;
                }
                if (__ptr[6] == pcVar7[6] + 6) {
                  psVar8 = &local_48;
                  if ((local_50 & 1) != 0) {
                    psVar8 = (size_t *)(local_40 + 7);
                  }
                  if (__ptr[7] == *(char *)psVar8 + 7) {
                    pcVar7 = local_40;
                    if ((local_50 & 1) == 0) {
                      pcVar7 = pcVar5;
                    }
                    if (__ptr[8] == pcVar7[8] + 8) {
                      pcVar7 = local_40;
                      if ((local_50 & 1) == 0) {
                        pcVar7 = pcVar5;
                      }
                      if (__ptr[9] == pcVar7[9] + 9) {
                        pcVar7 = local_40;
                        if ((local_50 & 1) == 0) {
                          pcVar7 = pcVar5;
                        }
                        if (__ptr[10] == pcVar7[10] + 10) {
                          pcVar7 = local_40;
                          if ((local_50 & 1) == 0) {
                            pcVar7 = pcVar5;
                          }
                          if (__ptr[0xb] == pcVar7[0xb] + 0xb) {
                            pcVar7 = local_40;
                            if ((local_50 & 1) == 0) {
                              pcVar7 = pcVar5;
                            }
                            if (__ptr[0xc] == pcVar7[0xc] + 0xc) {
                              pcVar7 = local_40;
                              if ((local_50 & 1) == 0) {
                                pcVar7 = pcVar5;
                              }
                              if (__ptr[0xd] == pcVar7[0xd] + 0xd) {
                                pcVar7 = local_40;
                                if ((local_50 & 1) == 0) {
                                  pcVar7 = pcVar5;
                                }
                                if (__ptr[0xe] == pcVar7[0xe] + 0xe) {
                                  ppcVar9 = (char **)(local_40 + 0xf);
                                  if ((local_50 & 1) == 0) {
                                    ppcVar9 = &local_40;
                                  }
                                  if (__ptr[0xf] == *(char *)ppcVar9 + 0xf) {
                                    pcVar7 = local_40;
                                    if ((local_50 & 1) == 0) {
                                      pcVar7 = pcVar5;
                                    }
                                    if (__ptr[0x10] == pcVar7[0x10] + 0x10) {
                                      pcVar7 = local_40;
                                      if ((local_50 & 1) == 0) {
                                        pcVar7 = pcVar5;
                                      }
                                      if (__ptr[0x11] == pcVar7[0x11] + 0x11) {
                                        pcVar7 = local_40;
                                        if ((local_50 & 1) == 0) {
                                          pcVar7 = pcVar5;
                                        }
                                        cVar1 = pcVar7[0x12];
                                        iVar2 = __ptr[0x12];
                                        free(__ptr);
                                        if (iVar2 == cVar1 + 0x12) {
                    /* try { // try from 00123c94 to 00123cb8 has its CatchHandler @ 00123d08 */
                                          (*(*param_1)->ReleaseStringUTFChars)
                                                    (param_1,param_3,chars);
                                          p_Var6 = (*(*param_1)->NewStringUTF)(param_1,"TRUE");
                                        }
                                        goto LAB_00123cc6;
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    free(__ptr);
  }
LAB_00123cc6:
  if ((local_50 & 1) != 0) {
    operator.delete(local_40);
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == local_38) {
    return p_Var6;
  }
LAB_00123d03:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

This is the function that verifies the password; we know for sure that:

* ```p_Var6``` returns either ```TRUE``` or ```FALSE``` after all the checks done by the if statements.
* ```uVar3``` is the length of the input string, and we also know that the password will be of length ```19```.
* The values in the memory address pointed to by ```__ptr``` are somehow related to the characters in the password.
* If we try to understand the logic of the checks performed, the hexadecimal values representing the ASCII characters of the input string are summed by a progressively increasing value depending on the position.

So, to find the password, we just need to convert the hexadecimal values declared in ```__ptr``` minus the position of the character:

| __ptr | - | = | ASCII |
|:-:|:-:|:-:|:-:|
|  0x50 | 0 | 0x50 | P |
|  0x55 | 1 | 0x54 | T |
|  0x54 | 2 | 0x52 | R |
|  0x7e | 3 | 0x7b | { |
|  0x4a | 4 | 0x46 | F |
|  0x71 | 5 | 0x6c | l |
|  0x7f | 6 | 0x79 | y |
|  0x54 | 7 | 0x4d | M |
|  0x6d | 8 | 0x65 | e |
|  0x5d | 9 | 0x54 | T |
|  0x79 | a | 0x6f | o |
|  0x5f | b | 0x54 | T |
|  0x74 | c | 0x68 | h |
|  0x72 | d | 0x65 | e |
|  0x5b | e | 0x4d | M |
|  0x7e | f | 0x6f | o |
|  0x7f | 10 | 0x6F | o |
|  0x7f | 11 | 0x6e | n |
|  0x8f | 12 | 0x7d | } |

So in the end we have:
`PTR{FlyMeToTheMoon}`

{{< music url="/posts/pwn-the-rover/20 - FLY ME TO THE MOON [TV. Size Version].flac" name="FLY ME TO THE MOON" artist="Bart Howard, Toshiyuki Ohmori & CLAIRE" cover="/posts/pwn-the-rover/nge.jpg" >}}










