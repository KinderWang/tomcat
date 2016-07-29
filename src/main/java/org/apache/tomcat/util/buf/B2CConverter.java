/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */


package org.apache.tomcat.util.buf;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Efficient conversion of bytes  to character .
 *  
 *  This uses the standard JDK mechansim - a reader - but provides mechanisms
 *  to recycle all the objects that are used. It is compatible with JDK1.1
 *  and up,
 *  ( nio is better, but it's not available even in 1.2 or 1.3 )
 *
 *  Not used in the current code, the performance gain is not very big
 *  in the current case ( since String is created anyway ), but it will
 *  be used in a later version or after the remaining optimizations.
 */
public class B2CConverter {
    
    
    private static org.apache.juli.logging.Log log=
        org.apache.juli.logging.LogFactory.getLog( B2CConverter.class );

    private static final Map<String, Charset> encodingToCharsetCache =
        new HashMap<String, Charset>();
    
    static {
        for (Charset charset: Charset.availableCharsets().values()) {
            encodingToCharsetCache.put(
                    charset.name().toLowerCase(Locale.US), charset);
            for (String alias : charset.aliases()) {
                encodingToCharsetCache.put(
                        alias.toLowerCase(Locale.US), charset);
            }
        }
    }

    public static Charset getCharset(String enc)
            throws UnsupportedEncodingException {

        // Encoding names should all be ASCII
        String lowerCaseEnc = enc.toLowerCase(Locale.US);
        
        Charset charset = encodingToCharsetCache.get(lowerCaseEnc);

        if (charset == null) {
            // Pre-population of the cache means this must be invalid
            throw new UnsupportedEncodingException(enc);
        }
        return charset;
    }

    private IntermediateInputStream iis;
    private ReadConvertor conv;
    private CharsetDecoder decoder;
    private String encoding;

    protected B2CConverter() {
    }
    
    /** Create a converter, with bytes going to a byte buffer
     */
    public B2CConverter(String encoding)
        throws IOException
    {
        this.encoding=encoding;
        reset();
    }

    
    /** Reset the internal state, empty the buffers.
     *  The encoding remain in effect, the internal buffers remain allocated.
     */
    public  void recycle() {
        conv.recycle();
        decoder.reset();
    }

    static final int BUFFER_SIZE=8192;
    char result[]=new char[BUFFER_SIZE];

    /** Convert a buffer of bytes into a chars
     * @deprecated
     */
    public  void convert( ByteChunk bb, CharChunk cb )
        throws IOException
    {
        // Set the ByteChunk as input to the Intermediate reader
        convert(bb, cb, cb.getBuffer().length - cb.getEnd());
    }

    /**
     * Convert a buffer of bytes into a chars.
     *
     * @param bb    Input byte buffer
     * @param cb    Output char buffer
     * @param limit Number of bytes to convert
     * @throws IOException
     */    
    public void convert( ByteChunk bb, CharChunk cb, int limit) 
        throws IOException
    {
        iis.setByteChunk( bb );
        try {
            // read from the reader
            int bbLengthBeforeRead  = 0;
            while( limit > 0 ) {
                int size = limit < BUFFER_SIZE ? limit : BUFFER_SIZE;
                bbLengthBeforeRead = bb.getLength();
                int cnt=conv.read( result, 0, size );
                if( cnt <= 0 ) {
                    // End of stream ! - we may be in a bad state
                    if( debug>0)
                        log( "EOF" );
                    return;
                }
                if( debug > 1 )
                    log("Converted: " + new String( result, 0, cnt ));
                cb.append( result, 0, cnt );
                limit = limit - (bbLengthBeforeRead - bb.getLength());
            }
        } catch( IOException ex) {
            if( debug>0)
                log( "Reseting the converter " + ex.toString() );
            reset();
            throw ex;
        }
    }


    public void reset() throws IOException {
        // Re-create the reader and iis
        iis = new IntermediateInputStream();
        decoder = getCharset(encoding).newDecoder();
        conv = new ReadConvertor(iis, decoder);
    }

    private final int debug=0;
    void log( String s ) {
        if (log.isDebugEnabled())
            log.debug("B2CConverter: " + s );
    }

    // -------------------- Not used - the speed improvemnt is quite small

    /*
    private Hashtable decoders;
    public static final boolean useNewString=false;
    public static final boolean useSpecialDecoders=true;
    private UTF8Decoder utfD;
    // private char[] conversionBuff;
    CharChunk conversionBuf;


    private  static String decodeString(ByteChunk mb, String enc)
        throws IOException
    {
        byte buff=mb.getBuffer();
        int start=mb.getStart();
        int end=mb.getEnd();
        if( useNewString ) {
            if( enc==null) enc="UTF8";
            return new String( buff, start, end-start, enc );
        }
        B2CConverter b2c=null;
        if( useSpecialDecoders &&
            (enc==null || "UTF8".equalsIgnoreCase(enc))) {
            if( utfD==null ) utfD=new UTF8Decoder();
            b2c=utfD;
        }
        if(decoders == null ) decoders=new Hashtable();
        if( enc==null ) enc="UTF8";
        b2c=(B2CConverter)decoders.get( enc );
        if( b2c==null ) {
            if( useSpecialDecoders ) {
                if( "UTF8".equalsIgnoreCase( enc ) ) {
                    b2c=new UTF8Decoder();
                }
            }
            if( b2c==null )
                b2c=new B2CConverter( enc );
            decoders.put( enc, b2c );
        }
        if( conversionBuf==null ) conversionBuf=new CharChunk(1024);

        try {
            conversionBuf.recycle();
            b2c.convert( this, conversionBuf );
            //System.out.println("XXX 1 " + conversionBuf );
            return conversionBuf.toString();
        } catch( IOException ex ) {
            ex.printStackTrace();
            return null;
        }
    }

    */
}

// -------------------- Private implementation --------------------



/**
 * 
 */
final class  ReadConvertor extends InputStreamReader {
    
    // Has a private, internal byte[8192]
    
    /** Create a converter.
     */
    public ReadConvertor(IntermediateInputStream in, CharsetDecoder decoder) {
        super(in, decoder);
    }
    
    /** Overriden - will do nothing but reset internal state.
     */
    public  final void close() throws IOException {
        // NOTHING
        // Calling super.close() would reset out and cb.
    }
    
    public  final int read(char cbuf[], int off, int len)
        throws IOException
    {
        // will do the conversion and call write on the output stream
        return super.read( cbuf, off, len );
    }
    
    /** Reset the buffer
     */
    public  final void recycle() {
        try {
            // Must clear super's buffer.
            while (ready()) {
                // InputStreamReader#skip(long) will allocate buffer to skip.
                read();
            }
        } catch(IOException ioe){
        }
    }
}


/** Special output stream where close() is overriden, so super.close()
    is never called.
    
    This allows recycling. It can also be disabled, so callbacks will
    not be called if recycling the converter and if data was not flushed.
*/
final class IntermediateInputStream extends InputStream {
    ByteChunk bc = null;
    
    public IntermediateInputStream() {
    }
    
    public  final void close() throws IOException {
        // shouldn't be called - we filter it out in writer
        throw new IOException("close() called - shouldn't happen ");
    }
    
    public  final  int read(byte cbuf[], int off, int len) throws IOException {
        return bc.substract(cbuf, off, len);
    }
    
    public  final int read() throws IOException {
        return bc.substract();
    }

    // -------------------- Internal methods --------------------


    void setByteChunk( ByteChunk mb ) {
        bc = mb;
    }

}
