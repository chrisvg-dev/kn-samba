package com.kn.samba;

import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        SmbRemoteAccess samba = new SmbRemoteAccess();
        //System.err.println( "Created: " + samba.write("", "My first file", "UTF8") );
        String files[] = samba.list("", "*");


    }
}