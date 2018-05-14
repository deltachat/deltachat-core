/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2017 Björn Petersen
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see http://www.gnu.org/licenses/ .
 *
 ******************************************************************************/

/**
 * For module testing activate __MRUUDECODE_TESTING__ (and __DEBUG__)
 */
//#define __MRUUDECODE_TESTING__
//#define __DEBUG__


#ifndef __MRUUDECODE_TESTING__
    #include "mrmailbox_internal.h"  // cs: Why is this include necessary? I see no reason !?
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mruudecode.h"

/**
 *  Locally needed function declarations
 *  This makes the order of function definitions independent from first use
 */

/* return hex representation of a string*/
char* mr_print_hex(char* s);

/* delivers one line from a string */
int   mr_getline (char** line, char* source, char** nextchar);

/* CR or CRLF or LF */
char* mr_detect_line_end (const char* txt);

/* checks if line matches uuencoded rules */
int   mr_uu_check_line(int n, int line_len);

/* find uuencoded part in msgtxt and returns it's position */
char* mr_find_uuencoded_part (const char* msgtxt);

/* extract uuencoded part and make it for next func available */
char* mr_handle_uuencoded_part (const char*   msgtxt,
                                 char*         uu_msg_start_pos,
                                 char**        ret_binary,
                                 size_t*       ret_binary_bytes,
                                 char**        ret_filename);

/* decode uuencoded part and provide it, used in mr_handle_uuencoded_part() */
int   mr_uudecode(char** ret_binary, size_t uudecoding_buffer_len, const char* uu_body_start);



/**
 *  Variables and preprocessor definitions
 */

/* for mr_detect_line_end */
#define CRLF "\r\n" //1310 dez
#define CR   "\r"   //13
#define LF   "\n"   //10

// prevent infinite loops
#define MAX_DECODING_LOOPS 20


// prevent infinite loops 
static int      uu_part_loop_cnt    = 0;

// keeps line end pattern for all functions
static char*    line_end_pattern    = NULL;

#ifdef __DEBUG__
    char in[100]; // for gets()
#endif


/**
 *  Function defintions
 */


/**
 * This function takes a text and returns this text stripped by the first uuencoded part;
 * the uuencoded part itself is returned by three return parameters.
 *
 * If there are no uuencoded parts, the function terminates fast by returning NULL.
 *
 * @param text Null-terminated text to search uuencode parts in.
 *     The text is not modified, instead, the modified text is returned on success.
 *
 * @param[out] ret_binary Points to a pointer that is set to the binary blob on
 *     success.
 *     The data is allocated with malloc() and must be free()'d by the caller.
 *     If no uuencoded part is found, this parameter is set to NULL and the function returns NULL.
 *
 * @param[out] ret_binary_bytes Points to an integer that should be set to
 *     binary blob bytes on success.
 *
 * @param[out] ret_filename Points to a pointer that should be set to the filename of the blob.
 *     The data is allocated with malloc() and must be free()'d by the caller.
 *     If no uuencoded part is found, this parameter is set to NULL and the function returns NULL.
 *
 * @return If uuencoded parts are found in the given text, the function returns the
 *     given text stripped by the first uuencode block.
 *     The caller will call mruudecode_do() again with this remaining text then.
 *     This way, multiple uuencoded parts can be stripped from a text.
 *     If no uuencoded parts are found or on errors, NULL is returned.
 */
char* mruudecode_do(const char* text, char** ret_binary, size_t* ret_binary_bytes, char** ret_filename)
{
	// CAVE: This function may be called in a loop until it returns NULL, so make sure not to create an invinitive look.

	if( text == NULL || ret_binary == NULL || ret_binary_bytes == NULL || ret_filename == NULL ) {
		goto cleanup; // bad parameters
	}

    /**
     *  new code from cs which works with uuencoded parts
     */
    char* uustartpos    = NULL;
    char* ret_msg_text  = NULL; // NULL = no uuencoded parts are found (standard case)
    
    
    if (++uu_part_loop_cnt > MAX_DECODING_LOOPS){
        // fence against infinite loops
        goto cleanup;
    }

    if (line_end_pattern == NULL){
        // we are in the first loop -> init
        
        line_end_pattern = mr_detect_line_end(text);
        if(line_end_pattern == NULL){
            #ifdef __DEBUG__
            printf("Error - Line End Pattern not detected - stopping here !\n\n");
            #endif
            goto cleanup;
        }
        #ifdef __DEBUG__
        printf("Line End = '%s'\n\n", line_end_pattern);
        #endif
    }
    
    uustartpos = mr_find_uuencoded_part(text);
    if (!uustartpos){
        #ifdef __DEBUG__
        puts("no or no further uu_part found\n\n");
        puts("printing now message after all mr_handle_uuencoded_part(s)\n\n");
        gets(in);
        puts(text);
        #endif

        // no or no further uu_parts found
        goto cleanup;
    }

    #ifdef __DEBUG__
    printf("uu_part found at pos: %.50s [......]\n\n", uustartpos);
    #endif

    ret_msg_text = mr_handle_uuencoded_part (text, uustartpos, ret_binary, ret_binary_bytes, ret_filename);
    
    #ifdef __DEBUG__
      puts("printing now message after mr_handle_uuencoded_part\n\n");
      gets(in);
      puts("go ....\n\n");
    #endif

    return ret_msg_text;
    

cleanup:
    // reset globals
    line_end_pattern = NULL;
    uu_part_loop_cnt = 0;

	return NULL;
}


/**
 *  Helper functions
 */

char* mr_print_hex (char* s){
    /**
     * make hex representation of a string
     * 
     * @Return
     *      hex representation of s (needs to be free'd)
     * 
     */
    int n = strlen(s);
    int i;
    char* hex = (char*)calloc((2*n+1), sizeof(char));
    
    for(i = 0; i<n; i++){
        sprintf(hex+i*2, "%02X", s[i]);
    }
    
    return hex;
    
} //mr_print_hex()


int mr_getline (char** ret_lineptr, char* source, char** ret_nextchar){
    /**
     * Extracts first line from a given string 
     *
     *  Parameters:
     * 
     *  @ret_lineptr   - returned line incl. line end chars
     *  @source        - input string
     *  @ret_nextchar  - pointer to next char after current line end
     *                   gives start ptr for next call of this function
     * 
     *  @Return: 
     *      strlen of line found (incl. line end chars but exclude '\0')
     *      0 if no line is read
     */
     
    if(!line_end_pattern){
        // error - no pattern defined
        return 0;
    }
     
    char* lineend   = source;
    char* start     = source;
    int   linelen   = 0;
    size_t len_line_end_pattern = strlen(line_end_pattern);

    *ret_lineptr = NULL;
    
    //printf(" mr_getline - len len_end_pattern %d\n", (int)len_line_end_pattern );

    //printf( "mr_getline - %d %d\n", (int)source, (int)start);
    
    if((lineend = strstr(start, line_end_pattern))){
        //printf("  mr_getline - Line End found\n");
        
        lineend += len_line_end_pattern; // this belongs to the line
        
        linelen = lineend - start; // len of line

        //printf("  mr_getline - linelen=%d\n", linelen);
        //printf("  mr_getline - first 7 chars=%.7s [...]\n", start);
        
        *ret_nextchar = lineend;
        
        *ret_lineptr = strndup(start, linelen);
        
        #ifdef __DEBUG__
        if( *ret_lineptr != NULL ){
            printf("  ** mr_getline - complete line found= (see below!)\n%s\n", *ret_lineptr);
        }
        #endif
    }
    
    return linelen;
} //mr_getline()


char* mr_detect_line_end (const char* txt){
    /**
     *  Detect line end if it is CRLF or LF or CR
     * 
     *  This function delivers the first detected line end in a string
     */

    if(strstr(txt, CRLF)){
        #ifdef __DEBUG__
        printf("Line End CRLF\n");
        #endif
        
        return CRLF;
    }
    else if(strstr(txt, LF)){
        #ifdef __DEBUG__
        printf("Line End LF\n");
        #endif
        
        return LF;
    }
    else if(strstr(txt, CR)){
        #ifdef __DEBUG__
        printf("Line End CR\n");
        #endif
        return CR;
    }
    
    #ifdef __DEBUG__
    printf("No line end found\n");
    #endif
    
    return NULL;
    
} //mr_detect_line_end()


int mr_uu_check_line (int n, int line_len){
    /**
     *  Checks if n describes the correct line length for given encoded len char line len
     * 
     *  Parameters:
     * 
     *  @n        - number of encoded bytes in a line
     *  @line_len - number of chars in encoded string with first len char
     * 
     *  example uuencoded line where n is 45 and 1st char describes this:
     * 
     *     M9&%T``!3"F6(A '_F5V2'G']1(A5%)L-,KFI!G+OR#70]]L'X8H`?S S2I@P
     *     ||
     *     |+-- from here data
     *     +--- len char
     */
     
    /* Calculate expected # of chars and pad if necessary */
    int expected;
    
    if (n > 0){
        expected = (n+2)/3*4;
    }
    else
        return 0;

    /* # of chars + len char is the expected line len*/
    return (line_len == expected + 1) ? 1 : 0;
    
} //mr_uu_check_line()


/**
 *      Main uudecoding functions
 */ 

char* mr_find_uuencoded_part (const char* msgtxt){
    /**
     *  Find uuencoded part in msgtxt & return it's position.
     *  If no part is found NULL is returned.
     */
     
    char* uu_part_pos = NULL;
    int len_line_end_pattern = strlen(line_end_pattern);
    
    char tofind[20] = "";
    
    strcat(tofind, line_end_pattern);
    strcat(tofind, "begin ");
    
    if( (uu_part_pos = strstr(msgtxt, tofind)) ){
        uu_part_pos += len_line_end_pattern;
        #ifdef __DEBUG__
        printf("uu found at %d\n", (int)(uu_part_pos - msgtxt));
        #endif
    }
    
    return uu_part_pos;
    
} //mr_find_uuencoded_part()


char* mr_handle_uuencoded_part (const char*   msgtxt,
                                 char*         uu_msg_start_pos,
                                 char**        ret_binary,
                                 size_t*       ret_binary_bytes,
                                 char**        ret_filename){
    /**
     *  Handle first (!) uuencoded part in a msg
     * 
     * Parameters:
     * 
     *  @msgtxt           - original msg
     *  @uu_msg_start_pos - start position of uuencoded part of msg
     *  @ret_binary       - returned uudecoded data block (to be free'd)
     *  @ret_binary_bytes - len of ret_binary
     *  @ret_filename     - detected filename from uuencoded data block (to be free'd)
     *
     *  @return          - msgtxt without included first uu_part (stripped)
     * 
     * 
     * Steps:
     * 
     *  1) verify start line and extract filename
     *  2) search for end of uu_part
     *      calculate size of uuencoded data block
     *      malloc memory for new message and uudecoded data block
     *  3) decode uu_part
     *       use mr_uudecode() for decoding
     *  4) replace uu_part in original message text by a link to file
     *  5) return stripped msgtxt for next loop (one loop handles one uu_part)
     *
     *     If only one uu_part is in msg then next loop will be quick :-)
     */
    
    /**
     *      1) verify start line and extract filename
     */ 
    int   mode;
    char  filename[200] = "";
    char* line;
    
    char* uu_body_start;
    char* uu_body_end;
    
    char* ret_msgtxt;
    int   nread;
    
    /* build format for first uuencoded line scan*/
    char SSCANF_FORMAT[20] = "begin %o %[^";
    strcat(SSCANF_FORMAT, line_end_pattern);
    strcat(SSCANF_FORMAT, "]");
    
    /* get and check 1st uuencoded start line*/
    nread = mr_getline(&line, uu_msg_start_pos, &uu_body_start);
    if(line && (nread > 0)){
        sscanf (line, SSCANF_FORMAT, &mode, filename);
        #ifdef __DEBUG__
        printf ("mr_handle_uuencoded_part - mode=%o, filename=%s\n", mode, filename);
        #endif
        free(line); line = NULL;

        int len_filename = strlen(filename);
        
        if(0 < mode && mode <= 777 && len_filename){
            #ifdef __DEBUG__
            printf ("mr_handle_uuencoded_part - uu_part verified\n");
            #endif
            
            *ret_filename = strdup(filename);
        }
        else{
            #ifdef __DEBUG__
            printf("mr_handle_uuencoded_part - uu_part not ok, stopping here!\n");
            #endif
            
            *ret_filename = NULL;
            return NULL;
        }
    }
    else
        return NULL;
    
    /**
     *      2) search for end of uuencoded part
     * 
     *   There are two possible ends defined:
     *     a) with a 'back quote'  and  (standard)
     *     b) with a 'blank char'       (not handled here!, future?)
     */
     
    /* build uu part end pattern */
    char uu_end_pattern[10] = "`";
    strcat(uu_end_pattern, line_end_pattern);
    strcat(uu_end_pattern, "end");
    strcat(uu_end_pattern, line_end_pattern);
    
    int uu_end_len = strlen(uu_end_pattern);

    #ifdef __DEBUG__
    printf("mr_handle_uuencoded_part - uu_end_pattern=%s", uu_end_pattern);
    #endif
    
    if((uu_body_end = strstr(uu_body_start, uu_end_pattern))){
        uu_body_end += uu_end_len;
        #ifdef __DEBUG__
        printf("mr_handle_uuencoded_part - Line End found, len=%d\n", (int)(uu_body_end - uu_body_start));
        #endif
    }
    else
        return NULL;
    
    
    /**
     *      3) Decode uuencoded part
     */
    int uu_body_len = uu_body_end - uu_body_start;
    

    /*  This is a high and rough estimation because 3 binary bytes are
     *  encoded in 4 chars (+ length char, + end_of_line_pattern, for each line ! )
     */
    int uudecoding_buffer_len = uu_body_len * 3 / 4;
    
    /* provide memory for decoding */
    *ret_binary = (char*) malloc(sizeof(char) * uudecoding_buffer_len );
    
    if (*ret_binary){
        *ret_binary_bytes = mr_uudecode(ret_binary, uudecoding_buffer_len, uu_body_start); 
        /**
         *  uudecoded data can be worked here
         *   store, print, returned or whatever ...
         * 
         *   it is simply returned here by func parameter !
         */
    }
    
    /**
     *      4) Replace uuencoded part in original message by a hint to filename
     * 
     *         Do this in each case without respect of uudecoding result.
     *         This is not checked.
     */ 

	int first_part_len = uu_msg_start_pos - msgtxt;
    
    ret_msgtxt  = (char*) malloc( sizeof(char) * strlen(msgtxt) );

	// keep first part
    strncpy(ret_msgtxt, msgtxt, first_part_len);
    ret_msgtxt[first_part_len] = '\0';

	// set hint for uuencoded message part
    sprintf(&ret_msgtxt[first_part_len], "[uuencoded attachment] - filename: %s%s", filename, line_end_pattern);
    
	// concat remaining part
	strcat(ret_msgtxt, uu_body_end );
    
	return ret_msgtxt;
    
} //mr_handle_uuencoded_part()



/* Single character decode.  */
#define	DEC(c)	(((c) - ' ') & 077)

int mr_uudecode(char** ret_binary, size_t uudecoding_buffer_len, const char* uu_body_start){
    /**
     *  Decode uuencoded part and provide it. Used in mr_handle_uuencoded_part
     * 
     *  Parameters:
     * 
     *  @ret_binary              - buffer where to write decoded data
     *  @uudecoding_buffer_len   - len of buffer of ret_binary
     *  @uu_body_start           - string with uuencoded data
     * 
     *  @return                 - number of decoded bytes
     */
    
    char* line;
    
    int   line_len;
    int   lineend_len = strlen(line_end_pattern);
    
    char* nextlinestart = (char*)uu_body_start;

    // line decoding
    char* p;
    char  ch;
    int   n;
    int   backquote_found = 0;
    int   ret_decoded_bytes = 0;

    #ifdef __DEBUG__
    char s [100] = "";
    char in[100];      // for gets, debugging
    #endif

    /* open stream for output*/
    FILE *fp = open_memstream(ret_binary, &uudecoding_buffer_len);

    #ifdef __DEBUG__
    printf("  mr_uudecode - uuencoded_txt_len=%d\n", uuencoded_txt_len);
    #endif
    
    //fputs("This is for testing only. No uuencoded data. Ignore this line!\n", fp);
    #ifdef __DEBUG__
    printf("  mr_uudecode - open file for output=%s\n", output_filename);
    #endif


    /**
     *  decoding line by line
     */
    while( (line_len = mr_getline (&line, nextlinestart, &nextlinestart)) ){
        /**
         *       Documentation of uuencoded lines
         * 
         *  - First char of line gives number of encoded bytes per line
         *    A standard line encodes 45 bytes of data.
         *    (45 encoded bytes means 60 chars per line, 61 chars in summary)
         *    "M........." means 45 bytes encoded / 60 chars are following
         * 
         *  - Every 4 char's block encodes 3 bytes of binary data,
         *     that means that number of chars in each line needs to be a multiple of 4 (!).
         *    This may be checked.
         *  
         *  - Each char's lower 6 bits are used for encoding.
         * 
         *  - Special handling for last line which may not encode full 3 bytes bunch 
         */

        #ifdef __DEBUG__
        //printf("  mr_uudecode - line = %s\n", line);
        //gets(in);
        #endif

        /* 1st: test for end of uuencoded data */
        if( 0 == strncmp(line, "`", 1) && (line_len - lineend_len) == 1){
            /* first line of end of uuencoded part found */

            //printf("  mr_uudecode -     *** single backquote found ***\n");
            backquote_found = 1;

            continue;
        }
        if( backquote_found && 0 == strncmp(line, "end", 3)){
            /* end of uuencoded part found */

            //printf("  mr_uudecode -     *** end of uuencoded part found ***\n");
            //fputs("This is for testing only. No uuencoded data. End of uuendcoded data detected!\n", fp);

            break;
        }
        
        /**
         *  2nd: Decoding one line 
         * 
         *   (source partly from uudecode.c (GNU, Free Software Foundation)) 
         */

        /* For each input line: */
        p = line;
        n = DEC (*p);  // n = number of encoded bytes

        // check line - compare given len with current line len
        // line[0] shows len info
        if (!mr_uu_check_line(n, line_len - lineend_len)){

            char msg[120];

            sprintf(msg, "  mr_uudecode() -    *** stop decoding, invalid line len, N=%d, line_len=%d ***\n", n, (line_len - lineend_len));

            #ifdef __DEBUG__
            puts(msg);
            #endif
            // write error msg to output file !
            fputs(msg, fp);

            break;
        }
        
        if (n <= 0){

            char msg[120];

            sprintf(msg, "  mr_uudecode() -    *** stop decoding, n <= 0, invalid line len %d ***\n", n);

            #ifdef __DEBUG__
            puts(msg);
            #endif
            // write error msg to output file !
            fputs(msg, fp);
            
            break;
        }

        //printf("  mr_uudecode -    n=%d\n", (int)n);
        
        if( ret_decoded_bytes < uudecoding_buffer_len - 3){
            // check for remaining buffer before decoding
            for (++p; n > 0; p += 4, n -= 3){
                if (n >= 3){
                    ch = DEC (p[0]) << 2 | DEC (p[1]) >> 4;
                    fputc((int)ch, fp);
                    ret_decoded_bytes++;
                    
                    ch = DEC (p[1]) << 4 | DEC (p[2]) >> 2;
                    fputc((int)ch, fp);
                    ret_decoded_bytes++;
                    
                    ch = DEC (p[2]) << 6 | DEC (p[3]);
                    fputc((int)ch, fp);
                    ret_decoded_bytes++;
                    
                    //printf("  mr_uudecode -    full block decoded\n");
                }
                else{
                    if (n >= 1){
                        ch = DEC (p[0]) << 2 | DEC (p[1]) >> 4;
                        fputc((int)ch, fp);
                        ret_decoded_bytes++;
                        //printf("  mr_uudecode -    n >= 1, n=%d decoded\n", n);
                    }
                    if (n >= 2){
                        ch = DEC (p[1]) << 4 | DEC (p[2]) >> 2;
                        fputc((int)ch, fp);
                        ret_decoded_bytes++;

                        //printf("  mr_uudecode -    n >= 2, n=%d decoded\n", n);
                    }
                }
            }
        }
        free(line);

    }
    #ifdef __DEBUG__
    printf("  mr_uudecode - close file for output=%s\n", output_filename);
    #endif
    fclose(fp);
    
    return ret_decoded_bytes;
} // mr_uudecode()







#ifdef __MRUUDECODE_TESTING__


/**
 * 
 *  Testing functions
 *  
 **/


char* ReadFile(char *filename, int* size){
    /**
     *  Read a full file in memory 
     */

   char     *buffer = NULL;
   int      string_size, read_size;
   FILE     *handler = fopen(filename, "r");

   if (handler)
   {
       // Seek the last byte of the file
       fseek(handler, 0, SEEK_END);
       // Offset from the first to the last byte, or in other words, filesize
       string_size = ftell(handler);
       // go back to the start of the file
       rewind(handler);

       // Allocate a string that can hold it all
       buffer = (char*) malloc(sizeof(char) * (string_size + 1) );

       // Read it all in one operation
       read_size = fread(buffer, sizeof(char), string_size, handler);
       *size = read_size;
       
       // fread doesn't set it so put a \0 in the last position
       // and buffer is now officially a string
       buffer[string_size] = '\0';

       if (string_size != read_size){
           // Something went wrong, throw away the memory and set
           // the buffer to NULL
           free(buffer); buffer = NULL;
       }

       // Always remember to close the file.
       fclose(handler);
    }

    return buffer;
}




/**
 *  Module test 
 */
 
int main()
{
    int   size    = 0;
    
    char* txt  = ReadFile("WG 1927 Problem geloest - musterdatei-2.eml", &size);
    
    //char* s = mr_print_hex(line_end_pattern);
    //printf("Test hex = '%s'\n\n", s);
    //free(s);
    
    /**
     *   The following code demonstrates using of mr_uudecode_do() function
     */
    if(txt) {

        char    *uu_blob        = NULL;
        char    *uu_filename    = NULL;
        char    *new_txt        = NULL;
        size_t  uu_blob_bytes   = 0;
        int     n=0;
        char    new_txt_filename[100];

        while( (new_txt = mruudecode_do(txt, &uu_blob, &uu_blob_bytes, &uu_filename)) != NULL)
        {
            /* open file for output*/
            FILE *fp = fopen(uu_filename, "w");
            int  i;

            for( i=0; i < uu_blob_bytes; i++){
                fputc((int)uu_blob[i], fp);
            }
            fclose(fp);

            sprintf(new_txt_filename, "new_text_%d.eml", n);

            FILE *fp1 = fopen(new_txt_filename, "w");
            
            fprintf(fp1, "%s", new_txt);
            fclose(fp1);

            n++;

            free(txt);         txt = new_txt;
            free(uu_blob);     uu_blob = NULL; uu_blob_bytes = 0;
            free(uu_filename); uu_filename = NULL;
        }

        free(txt);
        printf("File Size of testing file=%d\n", size);
    }else
        printf("   *** Empty or no Inputfile ! ***\n");

  
  return 0;
}



#endif /* __MRUUDECODE_TESTING__ */

