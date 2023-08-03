# group34汇总报告
## project1
生日攻击原理：假如随机选择n个人，那么这个n个人中有两个人的生日相同的概率是多少。如果要想概率是100%，那么只需要选择366个人就够了。因为只有365个生日日期。 如果想要概率达到99.9% ，那么只需要70个人就够了。而只需要23个人就能达到50%。    
sm3的输出范围是256位，那么我们的攻击就是找到两个不同的x，y，让f(x)=f(y)。即x和y发生了碰撞。根据概率论的公式，我们想要达到50%的几率，那么需要尝试的次数是:128位。但电脑能力达不到穷举128位，所以本实验尝试破解前面一些bit。    
要想观察前n个bit的碰撞，需向SM3随机输入2^(n/2)，并检测记录碰撞成功率。
## project2 The Rho method of reduced SM3
### 1、原理
![image](https://github.com/lumgroup34num1/project2/assets/129478488/28ff15a9-05a4-46cf-a854-6950ca353577)  
因子分解很多时候并不一定要把大整数n彻底分解成为素数的乘积，而可以求出n的某个非平凡因子。  
求解大整数的一个因子是困难的，但Euclidean算法告诉我们求两个数的最大公因子是O(logn)的时间可以得到的。
我们可以利用x和x'的碰撞使用Pollard Rho算法减少求解gcd的次数。
### 2、算法核心思想
只需要求得一个碰撞即可，不一定是x<sub>i</sub>和x<sub>j</sub>,也可以是x<sub>i+δ</sub>和x<sub>j+δ</sub>，所以在找碰撞的时候，不必逐个逐个求gcd，可以跳跃着求。由此我们可以进一步改进。
### 3、运行结果
![image](https://github.com/lumgroup34num1/project2/assets/129478488/ae5f359a-f587-43c8-a5fd-ad6f88f41877)
![image](https://github.com/lumgroup34num1/project2/assets/129478488/d611f632-c45f-4f16-833e-a114bad1f350)
![image](https://github.com/lumgroup34num1/project2/assets/129478488/ae7e6d24-9c76-42af-ac36-e9fe90ece31a)
![image](https://github.com/lumgroup34num1/project2/assets/129478488/acd9036f-8ec5-4f83-893b-dc03cae173b9)
![image](https://github.com/lumgroup34num1/project2/assets/129478488/4621767d-6147-4f7f-a242-04e87211e91d)
![image](https://github.com/lumgroup34num1/project2/assets/129478488/4642aeb2-2416-49c1-826d-046b32714f2e)
### 4、结果分析
随着需求碰撞位数的增加，rho形成的环大小成指数级增加，速度以及碰撞位数比起生日攻击显著提高。
## project3 length extension attack for SM3
### 1、实验原理
SM3的消息长度是64字节或者它的倍数，如果消息的长度不足则需要padding填充。  padding填充规则，首先填充一个1，随后填充0，直到消息长度为56(或者再加整数倍的64)字节，最后8字节用来填充消息的长度。  
在SM3函数计算时，首先对消息进行分组，每组64字节，每一次加密一组，并更新8个初始向量(初始值已经确定)，下一次用新向量去加密下一组，以此类推。我们可以利用这一特性去实现攻击。当我们得到第一次加密后的向量值时，再人为构造一组消息用于下一次加密，就可以在不知道secret的情况下得到合法的hash值，这是因为8个向量中的值便能表示第一轮的加密结果。
### 2、代码实现
```
uint32_t Padding_extend_attack(vector<bool>* input, uint32_t* M, uint64_t len)
{
	uint64_t size = (*input).size();
	uint32_t pad_size = (447 - size + 512) % 512, temp;
	size = size + 1 + (uint64_t)pad_size;
	(*input).push_back(1);											
	(*input).resize(size, 0);
	for (uint32_t i = 0; i < size; i += 32)
	{
		temp = 0;
		for (uint32_t j = 0; j < 31; ++j)
		{
			temp |= (*input)[i + j]; temp <<= 1;
		}
		temp |= (*input)[i + 31];
		M[(uint32_t)(i / 32)] = temp;
	}
	M[(uint32_t)(size / 32)] = (uint32_t)(len >> 32);							
	M[(uint32_t)(size / 32 + 1)] = ((uint32_t)len);
	return (uint32_t)((size / 32 + 2) / 16);
}
```
### 3、实验结果
![image](https://github.com/lumgroup34num1/project3/assets/129478488/691de1df-2f44-46f0-a029-c93163118d0e)
## project4 优化SM3
### 1、优化原理
利用UNROLLING循环展开，将循环体全部展开或者部分展开，从而提高应用程序的运行速度。

### 2、实验结果
![image](https://github.com/lumgroup34num1/project4/assets/129478488/9b548b63-9c72-4653-bb73-83f26298b9fd)

![image](https://github.com/lumgroup34num1/project4/assets/129478488/a3d75f25-7265-4cf1-b53d-3136a9b0d06a)
## project5 Impl Merkle Tree following RFC6962
### 1、实验原理
Merkle Tree即哈希树，本质上是一个哈希列表，在此基础上引入了树形结构，灵活性更强。  
Mercle Tree的叶子结点是数据块的hash值，非叶子结点是其对应子节点串联字符串的hash。
### 2、实验结果
#### 创建10w叶子结点的merkle tree
![image](https://github.com/lumgroup34num1/project5/assets/129478488/cfe0da19-c167-4e59-8022-b8e561b76392)
#### 存在性证明
![image](https://github.com/lumgroup34num1/project5/assets/129478488/2d6cb9e5-d921-40e9-8d9f-21cf7817cac0)
#### 不存在证明
![image](https://github.com/lumgroup34num1/project5/assets/129478488/f708c300-ef4f-4ec2-ba31-74e0ea0d5e67)
![image](https://github.com/lumgroup34num1/project5/assets/129478488/26d5c775-332b-49d4-8fed-c9df04c44d78)

## project9  AES / SM4 software implementation
### 1、实验原理
AES 加密算法共涉及 4 种操作：S盒（SubBytes）、行移位（ShiftRows）、列混合 （MixColumns）和轮密钥加（AddRoundKey）。以 AES-128 为例介绍AES的加密过程。首先对明文与原始密钥进行依次异或操作，从而避免不用密钥即可完成逆过程的可能，保证算法的安全性。然后进行10轮迭代加密，每一轮包括以下四个操作：字节代换，行移位，列混合，轮密钥加。注意最后一轮迭代不执行列混合操作。AES 解密算法的每一步分别对应加密算法的逆操作。加解密所有操作的顺序正好是相 反的，每轮的密钥分别由种子密钥经过密钥扩展算法得到。首先对密文进行一次轮密钥加操作。然后进行10轮迭代加密，每一轮顺序执行以下四个操作：逆行移位，逆字节代换，逆轮密钥加，逆列混合。注意最后一轮迭代不执行逆列混合操作。
### 2、实验结果
#### AES加密学号
第1轮:
55 65 57 53
54 64 50 57
30 00 31 52
a4 a4 a4 63  
第2轮:
bc 48 08 4f
a9 bf ae c8
0c 20 7c 4e
b5 0a 8f 8c  
第3轮:
9b fc 1d a1
2b 6a ec 4b
2f cb 60 ff
48 55 8c 3b  
第4轮:
1d 7a 1f f6
65 76 50 52
94 9d 59 bc
d5 f2 ed 76  
第5轮:
16 b4 39 68
a2 a1 12 9c
44 3e e1 d6
9b 99 f9 67  
第6轮:
3b 61 0f e8
61 ac 60 55
85 54 03 38
36 83 b1 d0  
第7轮:
0d 1f c4 46
80 4b 96 bf
17 a9 81 11
ca 54 52 cd  
第8轮:
9c 23 15 4d
b3 8b c3 45
c5 3d 88 98
b2 2a f3 18  
第9轮:
c6 5b 48 00
7f c1 17 34
c9 78 10 77
3b 43 8a 1a  
第a轮:
40 e9 3b 3f
9d 23 29 a9
21 9d f1 2e
69 60 36 63  
#### 时间比较
密码库：time=5.000000ms
手写：用时：119ms

## project10  report on the application of this deduce technique in Ethereum with ECDSA
![image](https://github.com/lumgroup34num1/project10/assets/129478488/50558964-3362-40ae-8364-e8ef025300da)
![image](https://github.com/lumgroup34num1/project10/assets/129478488/6666f5cd-bf3b-4e99-aa29-a2b8c0b794b5)


## project11 impl sm2 with RFC6979
### 1、实验原理
  ECDSA是ECC与DSA的结合，整个签名过程与DSA类似，所不一样的是签名中采取的算法为ECC，最后签名出来的值也是分为r,s。
签名过程如下：
1、选择一条椭圆曲线Ep(a,b)，和基点G；

2、选择私有密钥k（k<n，n为G的阶），利用基点G计算公开密钥K=kG；

3、产生一个随机整数r（r<n），计算点R=rG；

4、将原数据和点R的坐标值x,y作为参数，计算SHA1做为hash，即Hash=SHA1(原数据,x,y)；

5、计算s≡r - Hash * k (mod n)

6、r和s做为签名值，如果r和s其中一个为0，重新从第3步开始执行

验证过程如下：

1、接受方在收到消息(m)和签名值(r,s)后，进行以下运算

2、计算：sG+H(m)P=(x1,y1), r1≡ x1 mod p。

3、验证等式：r1 ≡ r mod p。

4、如果等式成立，接受签名，否则签名无效。
### 2、运行结果
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/552d778b-2ec4-42fd-a013-229a09e4de1b)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/6aeca06a-c309-458d-9211-1cc62c303965)
## project 12 verify the above pitfalls with proof-of-concept code

### 实验步骤

&emsp;&emsp;其中3个算法的signature pitfalls原理大致相同，此处前四种情况以sm2为例，伪造签名以ECDSA为例，其它算法的原理可见代码注释，此处不再重复。

#### 1. Leaking k leads to leaking of d

![leakingk.png](https://s2.loli.net/2022/07/27/v3cOR4KTup8jtwB.png)

#### 2. Reusing k leads to leaking of d

![reusing k.png](https://s2.loli.net/2022/07/27/RZWp81JgKueoIbw.png)

#### 3. Tow users's same k leaks d

![diff k.png](https://s2.loli.net/2022/07/27/Dfg2NPBRYMCA8ZV.png)

#### 4. same d and k with ECDSA lead to leaking of d

![withecdsa.png](https://s2.loli.net/2022/07/27/TD53pxFdywRI9oM.png)

#### 5. Forge signature if only H(m) is checked

![伪造原理.png](https://s2.loli.net/2022/07/27/LWVSTnaitY2jskC.png)
### 实验结果
    
&emsp;&emsp;完成了表格中三个算法的大部分signature pitfalls，包括ECDSA、Schnorr、SM2-Sig算法的泄露k、重复使用k、不同用户使用相同k、与ECDSA算法使用相同k造成私钥泄露的实例，完成了ECDSA和Schnorr算法的仅提供H(m)下的签名伪造实例。
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/7e38d7d2-3605-4af7-b2bc-8786b9230a0a)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/97933815-8f55-4197-a249-c3ff27c50d96)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/34aca231-c2f3-46c3-ae02-b43b3baead25)



### project13 Implement the above ECMH scheme
使用SM3算法  
映射方式为转化数字映射到x  
若不存在点（X,Y），或者说(pow(x1,3,p)+a*x1+b)%p不是p的二次剩余，则对X加1，再次尝试。
![image](https://github.com/lumgroup34num1/project13/assets/129478488/779307cc-96e5-415f-9b03-7e4dedcdd0f0)

## project 14 Implement a PGP scheme with SM2
### 1、实验原理
两方PGP通信采用TCP通信模拟真实网络通信过程，使用sm2密钥协商算法协商对称密钥，再使用AES加密以协商得到的密钥加密临时会话密钥，并使用AES加密以临时会话密钥加密通信消息。
### 2、实验结果
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/8733a5d6-441a-4ecb-adf7-0a1ff76442e8)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/b0589df7-5362-4644-86ce-4e9ec09ed7e8)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/63208b8e-95f8-4244-93d5-9836c0ae7ae5)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/8a7c4958-5243-4aa1-b84b-cb172498c8a7)
## project 15 implement sm2 2P sign with real network communication
### 1、实验原理
![sig.png](https://s2.loli.net/2022/07/28/quDUW4d1tXr2ayM.png)
<p align="center">两方SM2签名原理</p>

### 2、实验结果
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/4e09d4ae-a030-43d5-8634-4541938b0bc8)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/cc8d31a8-5755-4e0d-b6c6-da12c4543367)

## project 16 implement sm2 2P decrypt with real network communication
### 1、实验原理
![dec.png](https://s2.loli.net/2022/07/28/IH1CRJBVi74xZ2n.png)
<p align="center">两方SM2解密原理</p>

### 2、实验结果
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/9cedb6f0-ae3e-4935-9bc3-d6a83c0694be)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/9b608455-d909-4645-af27-96aedf836d84)

## project 17  PoC impl of the scheme, or do implement analysis by Google
### 1、实验原理
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/eac60fb2-200b-4cc5-897f-9a2e750f17dd)
采用TCP通信模拟真实网络通信过程，完成了模拟Google Password Checkup，效果为能在用户不向服务器泄露私钥、服务器不向用户透露已泄露密码的前提下使用户检查服务器泄露密码库中是否有自己的密码从而进行检测，部分原理类似DH密钥交换。
### 2、实验结果
![pascheck_server.png](https://s2.loli.net/2022/07/30/ELncHd4DyKXPuQf.png)

## project18  send a tx on Bitcoin testnet, and parse the tx data down to every bit, better write script yourself
### 1、实验原理

![block.jpeg](https://s2.loli.net/2022/07/27/vwaiTqSogrBNx9d.png)

  由于比特币区块的各个字段的位置和长度相对固定，因此根据结构拆解出HEADER、Coinbase Trade、Common Trade部分并解释出各字段值即可。此处实际完成了获取测试网地址并申请比特币和发布交易。
### 2、实验结果
![image](https://github.com/lumgroup34num1/project18/assets/129478488/d765c9a2-4b0b-4c6d-98a1-9c2aa6049cde)  

结果文件已上传

## project19 forge a signature to pretend that you are Satoshi

ECDSA算法在仅要求指定H(m)和拥有正确签名的情况下很容易伪造签名。
### 实验结果
![image](https://github.com/lumgroup34num1/project19/assets/129478488/129b5614-adb6-4687-81af-dd777200d1eb)

## project21 research report on MPT
![image](https://github.com/lumgroup34num1/project21/assets/129478488/c5041431-b284-4242-8366-fe801a2ceb9a)


&emsp;&emsp;对MTP整体结构进行理解，并对开源MTP代码进行对照注释。


