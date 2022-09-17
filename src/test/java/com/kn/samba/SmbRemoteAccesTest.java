package com.kn.samba;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class SmbRemoteAccesTest {

    @Test
    @DisplayName("Launching first test")
    public void firstTest(){
        String expected = "hello";
        String real = "hello";
        Assertions.assertEquals(expected, real);
    }

}
