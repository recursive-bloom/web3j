/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.web3j.crypto;

import org.junit.jupiter.api.Test;
import org.web3j.utils.Numeric;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.web3j.utils.Numeric.asByte;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HashTest {

    @Test
    public void testSha3() {
        byte[] input =
                new byte[] {
                    asByte(0x6, 0x8),
                    asByte(0x6, 0x5),
                    asByte(0x6, 0xc),
                    asByte(0x6, 0xc),
                    asByte(0x6, 0xf),
                    asByte(0x2, 0x0),
                    asByte(0x7, 0x7),
                    asByte(0x6, 0xf),
                    asByte(0x7, 0x2),
                    asByte(0x6, 0xc),
                    asByte(0x6, 0x4)
                };

        byte[] expected =
                new byte[] {
                    asByte(0x4, 0x7),
                    asByte(0x1, 0x7),
                    asByte(0x3, 0x2),
                    asByte(0x8, 0x5),
                    asByte(0xa, 0x8),
                    asByte(0xd, 0x7),
                    asByte(0x3, 0x4),
                    asByte(0x1, 0xe),
                    asByte(0x5, 0xe),
                    asByte(0x9, 0x7),
                    asByte(0x2, 0xf),
                    asByte(0xc, 0x6),
                    asByte(0x7, 0x7),
                    asByte(0x2, 0x8),
                    asByte(0x6, 0x3),
                    asByte(0x8, 0x4),
                    asByte(0xf, 0x8),
                    asByte(0x0, 0x2),
                    asByte(0xf, 0x8),
                    asByte(0xe, 0xf),
                    asByte(0x4, 0x2),
                    asByte(0xa, 0x5),
                    asByte(0xe, 0xc),
                    asByte(0x5, 0xf),
                    asByte(0x0, 0x3),
                    asByte(0xb, 0xb),
                    asByte(0xf, 0xa),
                    asByte(0x2, 0x5),
                    asByte(0x4, 0xc),
                    asByte(0xb, 0x0),
                    asByte(0x1, 0xf),
                    asByte(0xa, 0xd)
                };

        byte[] result = Hash.sha3(input);
        assertArrayEquals(result, (expected));
    }

    @Test
    public void testSha3HashHex() {
        assertEquals(
                Hash.sha3(""),
                ("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));

        assertEquals(
                Hash.sha3("68656c6c6f20776f726c64"),
                ("0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"));
    }

    @Test
    public void testSha3String() {
        assertEquals(
                Hash.sha3String(""),
                ("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));

        assertEquals(
                Hash.sha3String("EVWithdraw(address,uint256,bytes32)"),
                ("0x953d0c27f84a9649b0e121099ffa9aeb7ed83e65eaed41d3627f895790c72d41"));
    }

    @Test
    public void testByte() {
        assertEquals(asByte(0x0, 0x0), ((byte) 0x0));
        assertEquals(asByte(0x1, 0x0), ((byte) 0x10));
        assertEquals(asByte(0xf, 0xf), ((byte) 0xff));
        assertEquals(asByte(0xc, 0x5), ((byte) 0xc5));
    }

    public static String nameToNode(String nameStr, String parentHexStr) {
        String nameHash = Hash.sha3String(nameStr);

        byte[] parentArray = Numeric.hexStringToByteArray(parentHexStr);
        byte[] nameArray = Numeric.hexStringToByteArray(nameHash);
        byte[] temp = new byte[parentArray.length + nameArray.length];

        System.arraycopy(parentArray, 0, temp, 0, parentArray.length);
        System.arraycopy(nameArray, 0, temp, parentArray.length, nameArray.length);

        byte[] nameNode = Hash.sha3(temp);
        String nameNodeHexStr = Numeric.toHexString(nameNode);
        System.out.println(nameNodeHexStr);
        return nameNodeHexStr;
    }

    @Test
    public void testDidNameToNode() {

        // root Node == sha3("");
        // verse Node == sha3(rootNode + sha3("verse"));
        // foobar.verse Node == sha3(verseNode + sha3("foobar"));
        // www.foobar.verse Node == sha3(foobarNode + sha3("www"));

        // root Node: 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        // verse Node: 0xc14d68eb0d0a4df33c3656bc9e67e9cd0af9811668568c61c0c7e98ac830bdfa
        // foobar.verse Node: 0x02532798adbc24b7463d2984f38e9caa99661be4b772fbbaa15842d1a52ebf0a
        // alice.foobar.verse Node: 0xb8ed50a2dcd9fcb01a597b2c0ee72ba303309a1f7ec384ac4f666f87b08e3709
        // www.foobar.verse Node: 0x7ebb34bbb6b0dad285333443261c81c623b1ccd2052a9982eb0da01168915556

        String rootNodeHexStr = Hash.sha3String(""); // root
        // BigInteger rootInt = Numeric.toBigInt(rootHash);
        System.out.println(rootNodeHexStr);

        String verseNodeHexStr = nameToNode("verse", rootNodeHexStr); // verse
        String foobarNodeHexStr = nameToNode("foobar", verseNodeHexStr); // foobar.verse
        String aliceNodeHexStr = nameToNode("alice", foobarNodeHexStr); // alice.foobar.verse
        String wwwNodeHexStr = nameToNode("www", foobarNodeHexStr); // www.foobar.verse

    }

}
