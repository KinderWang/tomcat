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
package org.apache.coyote.http11.filters;

import java.io.EOFException;
import java.io.IOException;
import java.util.Locale;

import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.HexUtils;
import org.apache.coyote.InputBuffer;
import org.apache.coyote.Request;
import org.apache.coyote.http11.Constants;
import org.apache.coyote.http11.InputFilter;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.res.StringManager;

/**
 * Chunked input filter. Parses chunked data according to
 * <a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1">http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1</a><br>
 * 
 * @author Remy Maucherat
 * @author Filip Hanik
 */
public class ChunkedInputFilter implements InputFilter {

    private static final StringManager sm = StringManager.getManager(
            ChunkedInputFilter.class.getPackage().getName());


    // -------------------------------------------------------------- Constants

    protected static final String ENCODING_NAME = "chunked";
    protected static final ByteChunk ENCODING = new ByteChunk();


    // ----------------------------------------------------- Static Initializer

    static {
        ENCODING.setBytes(ENCODING_NAME.getBytes(), 0, ENCODING_NAME.length());
    }


    // ----------------------------------------------------- Instance Variables

    /**
     * Next buffer in the pipeline.
     */
    protected InputBuffer buffer;


    /**
     * Number of bytes remaining in the current chunk.
     */
    protected int remaining = 0;


    /**
     * Position in the buffer.
     */
    protected int pos = 0;


    /**
     * Last valid byte in the buffer.
     */
    protected int lastValid = 0;


    /**
     * Read bytes buffer.
     */
    protected byte[] buf = null;


    /**
     * Byte chunk used to read bytes.
     */
    protected ByteChunk readChunk = new ByteChunk();


    /**
     * Flag set to true when the end chunk has been read.
     */
    protected boolean endChunk = false;


    /**
     * Byte chunk used to store trailing headers.
     */
    protected ByteChunk trailingHeaders;

    {
        trailingHeaders = new ByteChunk();
        if (org.apache.coyote.Constants.MAX_TRAILER_SIZE > 0) {
            trailingHeaders.setLimit(org.apache.coyote.Constants.MAX_TRAILER_SIZE);
        }
    }


    /**
     * Size of extensions processed for this request.
     */
    private long extensionSize;
    
    
    /**
     * Flag that indicates if an error has occurred.
     */
    private boolean error;

    /**
     * Flag set to true if the next call to doRead() must parse a CRLF pair
     * before doing anything else.
     */
    protected boolean needCRLFParse = false;


    /**
     * Request being parsed.
     */
    private Request request;


    // ---------------------------------------------------- InputBuffer Methods

    /**
     * Read bytes.
     * 
     * @return If the filter does request length control, this value is
     * significant; it should be the number of bytes consumed from the buffer,
     * up until the end of the current request body, or the buffer length, 
     * whichever is greater. If the filter does not do request body length
     * control, the returned value should be -1.
     */
    public int doRead(ByteChunk chunk, Request req) throws IOException {
        if (endChunk) {
            return -1;
        }

        checkError();

        if(needCRLFParse) {
            needCRLFParse = false;
            parseCRLF(false);
        }

        if (remaining <= 0) {
            if (!parseChunkHeader()) {
                throwIOException(sm.getString("chunkedInputFilter.invalidHeader"));
            }
            if (endChunk) {
                parseEndChunk();
                return -1;
            }
        }

        int result = 0;

        if (pos >= lastValid) {
            if (readBytes() < 0) {
                throwIOException(sm.getString("chunkedInputFilter.eos"));
            }
        }

        if (remaining > (lastValid - pos)) {
            result = lastValid - pos;
            remaining = remaining - result;
            chunk.setBytes(buf, pos, result);
            pos = lastValid;
        } else {
            result = remaining;
            chunk.setBytes(buf, pos, remaining);
            pos = pos + remaining;
            remaining = 0;
            //we need a CRLF
            if ((pos+1) >= lastValid) {   
                //if we call parseCRLF we overrun the buffer here
                //so we defer it to the next call BZ 11117
                needCRLFParse = true;
            } else {
                parseCRLF(false); //parse the CRLF immediately
            }
        }

        return result;
    }


    // ---------------------------------------------------- InputFilter Methods

    /**
     * Read the content length from the request.
     */
    public void setRequest(Request request) {
        this.request = request;
    }


    /**
     * End the current request.
     */
    public long end() throws IOException {
        int maxSwallowSize = org.apache.coyote.Constants.MAX_SWALLOW_SIZE;
        long swallowed = 0;
        int read = 0;
        // Consume extra bytes : parse the stream until the end chunk is found
        while ((read = doRead(readChunk, null)) >= 0) {
            swallowed += read;
            if (maxSwallowSize > -1 && swallowed > maxSwallowSize) {
                throwIOException(sm.getString("inputFilter.maxSwallow"));
            }
        }

        // Return the number of extra bytes which were consumed
        return lastValid - pos;
    }


    /**
     * Amount of bytes still available in a buffer.
     */
    public int available() {
        return lastValid - pos;
    }
    

    /**
     * Set the next buffer in the filter pipeline.
     */
    public void setBuffer(InputBuffer buffer) {
        this.buffer = buffer;
    }


    /**
     * Make the filter ready to process the next request.
     */
    public void recycle() {
        remaining = 0;
        pos = 0;
        lastValid = 0;
        endChunk = false;
        needCRLFParse = false;
        trailingHeaders.recycle();
        if (org.apache.coyote.Constants.MAX_TRAILER_SIZE > 0) {
            trailingHeaders.setLimit(org.apache.coyote.Constants.MAX_TRAILER_SIZE);
        }
        extensionSize = 0;
        error = false;
    }


    /**
     * Return the name of the associated encoding; Here, the value is 
     * "identity".
     */
    public ByteChunk getEncodingName() {
        return ENCODING;
    }


    // ------------------------------------------------------ Protected Methods

    /**
     * Read bytes from the previous buffer.
     */
    protected int readBytes() throws IOException {

        int nRead = buffer.doRead(readChunk, null);
        pos = readChunk.getStart();
        lastValid = pos + nRead;
        buf = readChunk.getBytes();

        return nRead;
    }


    /**
     * Parse the header of a chunk.
     * A chunk header can look like 
     * A10CRLF
     * F23;chunk-extension to be ignoredCRLF
     * The letters before CRLF but after the trailer mark, must be valid hex digits, 
     * we should not parse F23IAMGONNAMESSTHISUP34CRLF as a valid header
     * according to spec
     */
    protected boolean parseChunkHeader() throws IOException {

        int result = 0;
        boolean eol = false;
        int readDigit = 0;
        boolean extension = false;

        while (!eol) {

            if (pos >= lastValid) {
                if (readBytes() <= 0)
                    return false;
            }

            if (buf[pos] == Constants.CR || buf[pos] == Constants.LF) {
                parseCRLF(false);
                eol = true;
            } else if (buf[pos] == Constants.SEMI_COLON && !extension) {
                // First semi-colon marks the start of the extension. Further
                // semi-colons may appear to separate multiple chunk-extensions.
                // These need to be processed as part of parsing the extensions.
                extension = true;
                extensionSize++;
            } else if (!extension) { 
                //don't read data after the trailer
                int charValue = HexUtils.getDec(buf[pos]);
                if (charValue != -1 && readDigit < 8) {
                    readDigit++;
                    result = (result << 4) | charValue;
                } else {
                    //we shouldn't allow invalid, non hex characters
                    //in the chunked header
                    return false;
                }
            } else {
                // Extension 'parsing'
                // Note that the chunk-extension is neither parsed nor
                // validated. Currently it is simply ignored.
                extensionSize++;
                if (org.apache.coyote.Constants.MAX_EXTENSION_SIZE > -1 &&
                        extensionSize > org.apache.coyote.Constants.MAX_EXTENSION_SIZE) {
                    throwIOException(sm.getString("chunkedInputFilter.maxExtension"));
                }
            }

            // Parsing the CRLF increments pos
            if (!eol) {
                pos++;
            }
        }

        if (readDigit == 0 || result < 0) {
            return false;
        }

        if (result == 0) {
            endChunk = true;
        }

        remaining = result;
        if (remaining < 0) {
            return false;
        }

        return true;
    }


    /**
     * Parse CRLF at end of chunk.
     * @deprecated  Use {@link #parseCRLF(boolean)}
     */
    @Deprecated
    protected boolean parseCRLF() throws IOException {
        parseCRLF(false);
        return true;
    }

    /**
     * Parse CRLF at end of chunk.
     *
     * @param   tolerant    Should tolerant parsing (LF and CRLF) be used? This
     *                      is recommended (RFC2616, section 19.3) for message
     *                      headers.
     */
    protected void parseCRLF(boolean tolerant) throws IOException {

        boolean eol = false;
        boolean crfound = false;

        while (!eol) {
            if (pos >= lastValid) {
                if (readBytes() <= 0) {
                    throwIOException(sm.getString("chunkedInputFilter.invalidCrlfNoData"));
                }
            }

            if (buf[pos] == Constants.CR) {
                if (crfound) {
                    throwIOException(sm.getString("chunkedInputFilter.invalidCrlfCRCR"));
                }
                crfound = true;
            } else if (buf[pos] == Constants.LF) {
                if (!tolerant && !crfound) {
                    throwIOException(sm.getString("chunkedInputFilter.invalidCrlfNoCR"));
                }
                eol = true;
            } else {
                throwIOException(sm.getString("chunkedInputFilter.invalidCrlf"));
            }

            pos++;
        }
    }


    /**
     * Parse end chunk data.
     */
    protected boolean parseEndChunk() throws IOException {
        // Handle optional trailer headers
        while (parseHeader()) {
            // Loop until we run out of headers
        }
        return true;
    }

    
    private boolean parseHeader() throws IOException {

        MimeHeaders headers = request.getMimeHeaders();

        byte chr = 0;

        // Read new bytes if needed
        if (pos >= lastValid) {
            if (readBytes() <0) {
               throwEOFException(sm.getString("chunkedInputFilter.eosTrailer"));
            }
        }
    
        chr = buf[pos];

        // CRLF terminates the request
        if (chr == Constants.CR || chr == Constants.LF) {
            parseCRLF(false);
            return false;
        }
    
        // Mark the current buffer position
        int startPos = trailingHeaders.getEnd();
    
        //
        // Reading the header name
        // Header name is always US-ASCII
        //
    
        boolean colon = false;
        while (!colon) {
    
            // Read new bytes if needed
            if (pos >= lastValid) {
                if (readBytes() <0) {
                    throwEOFException(sm.getString("chunkedInputFilter.eosTrailer"));
                }
            }
    
            chr = buf[pos];
            if ((chr >= Constants.A) && (chr <= Constants.Z)) {
                chr = (byte) (chr - Constants.LC_OFFSET);
            }

            if (chr == Constants.COLON) {
                colon = true;
            } else {
                trailingHeaders.append(chr);
            }
    
            pos++;
    
        }
        int colonPos = trailingHeaders.getEnd();
        
        //
        // Reading the header value (which can be spanned over multiple lines)
        //
    
        boolean eol = false;
        boolean validLine = true;
        int lastSignificantChar = 0;
    
        while (validLine) {
    
            boolean space = true;
    
            // Skipping spaces
            while (space) {
    
                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (readBytes() <0) {
                        throwEOFException(sm.getString("chunkedInputFilter.eosTrailer"));
                    }
                }
    
                chr = buf[pos];
                if ((chr == Constants.SP) || (chr == Constants.HT)) {
                    pos++;
                    // If we swallow whitespace, make sure it counts towards the
                    // limit placed on trailing header size (if there is one)
                    if (trailingHeaders.getLimit() != -1) {
                        int newlimit = trailingHeaders.getLimit() -1;
                        if (trailingHeaders.getEnd() > newlimit) {
                            throwIOException(sm.getString("chunkedInputFilter.maxTrailer"));
                        }
                        trailingHeaders.setLimit(newlimit);
                    }
                } else {
                    space = false;
                }
    
            }
    
            // Reading bytes until the end of the line
            while (!eol) {
    
                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (readBytes() <0) {
                        throwEOFException(sm.getString("chunkedInputFilter.eosTrailer"));
                    }
                }
    
                chr = buf[pos];
                if (chr == Constants.CR || chr == Constants.LF) {
                    parseCRLF(true);
                    eol = true;
                } else if (chr == Constants.SP) {
                    trailingHeaders.append(chr);
                } else {
                    trailingHeaders.append(chr);
                    lastSignificantChar = trailingHeaders.getEnd();
                }
    
                if (!eol) {
                    pos++;
                }
            }
    
            // Checking the first character of the new line. If the character
            // is a LWS, then it's a multiline header
    
            // Read new bytes if needed
            if (pos >= lastValid) {
                if (readBytes() <0) {
                    throwEOFException(sm.getString("chunkedInputFilter.eosTrailer"));
                }
            }
    
            chr = buf[pos];
            if ((chr != Constants.SP) && (chr != Constants.HT)) {
                validLine = false;
            } else {
                eol = false;
                // Copying one extra space in the buffer (since there must
                // be at least one space inserted between the lines)
                trailingHeaders.append(chr);
            }
    
        }
    
        String headerName = new String(trailingHeaders.getBytes(), startPos,
                colonPos - startPos, "ISO_8859_1");
        if (org.apache.coyote.Constants.ALLOWED_TRAILER_HEADERS.contains(
                headerName.toLowerCase(Locale.ENGLISH))) {
            MessageBytes headerValue = headers.addValue(headerName);
            
            // Set the header value
            headerValue.setBytes(trailingHeaders.getBytes(), colonPos,
                    lastSignificantChar - colonPos);
        }

        return true;
    }


    private void throwIOException(String msg) throws IOException {
        error = true;
        throw new IOException(msg);
    }


    private void throwEOFException(String msg) throws IOException {
        error = true;
        throw new EOFException(msg);
    }


    private void checkError() throws IOException {
        if (error) {
            throw new IOException(sm.getString("chunkedInputFilter.error"));
        }
    }
}
