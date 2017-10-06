package com.riddleandcode.vault.utils;

import java.util.Enumeration;
import java.util.Hashtable;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.sec.SECObjectIdentifiers;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.util.Strings;

public class ECCNamedCurves {

    private static final Hashtable<String, ASN1ObjectIdentifier> objIds = new Hashtable<String, ASN1ObjectIdentifier>();
    private static final Hashtable<ASN1ObjectIdentifier, String> names = new Hashtable<ASN1ObjectIdentifier, String>();

    private static void defineCurve(String name, ASN1ObjectIdentifier oid) {
        objIds.put(name, oid);
        names.put(oid, name);
    }

    static {
        defineCurve("B-283", SECObjectIdentifiers.sect283r1);
        defineCurve("B-233", SECObjectIdentifiers.sect233r1);
        defineCurve("K-283", SECObjectIdentifiers.sect283k1);
        defineCurve("K-233", SECObjectIdentifiers.sect233k1);
    }

    public static X9ECParameters getByName(String name) {
        ASN1ObjectIdentifier oid = objIds.get(Strings.toUpperCase(name));

        if (oid != null) {
            return getByOID(oid);
        }
        return null;
    }

    /**
     * return the X9ECParameters object for the named curve represented by
     * the passed in object identifier. Null if the curve isn't present.
     *
     * @param oid an object identifier representing a named curve, if present.
     */
    private static X9ECParameters getByOID(ASN1ObjectIdentifier oid) {
        return SECNamedCurves.getByOID(oid);
    }

    /**
     * return the object identifier signified by the passed in name. Null
     * if there is no object identifier associated with name.
     *
     * @return the object identifier associated with name, if present.
     */
    public static ASN1ObjectIdentifier getOID(String name) {
        return objIds.get(Strings.toUpperCase(name));
    }



    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(ASN1ObjectIdentifier oid) {
        return names.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for curves
     * contained in this structure.
     */
    public static Enumeration<String> getNames() {
        return objIds.keys();
    }
}
