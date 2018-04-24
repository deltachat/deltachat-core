/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2018 Christian Schneider
 *                          Contact: schneider17@gmx.de
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

#include "stdio.h"
#include <stdlib.h>

#include "string.h"
#include "mruudecode.h"


#define __MRUUDECODE_TESTING__

//#define __DEBUG__



/***********************************************************************
 *  helper functions
 */

char* mr_print_hex(char* s){
    /*
     * make hex representation of a string
     */
    int n = strlen(s);
    int i;
    char* hex = (char*)calloc((2*n+1), sizeof(char));
    
    for(i = 0; i<n; i++){
        sprintf(hex+i*2, "%02X", s[i]);
    }
    
    return hex;
}


int mr_getline (char** line, char* source, char* lineendpattern, char** nextchar){
    /*
     * extracts first line from a given string 
     * skips newline and empty lines at beginning
     * 
     *  Parameters:
     * 
     * line             - returned line incl. line end chars
     * source           - input string
     * lineendpattern   - pattern of used lineend CRLF or LFCR or CR or LF
     * nextchar         - pointer to next char after current line end
     * 
     * 
     *  Return value:
     * 
     * strlen of line found (incl. line end chars but exclude '\0')
     * 0 if no line is read
     * 
     */
     
    char* lineend;
    char* start;
    int   linelen = 0;
    size_t len_lineendpattern = strlen(lineendpattern);

    //printf("  mr_getline - len lenendpattern %d\n", (int)len_lineendpattern );
    
    start = lineend = source ;

    //printf( "mr_getline - %d %d\n", (int)source, (int)start);
    
    if((lineend = strstr(start, lineendpattern))){
        //printf("  mr_getline - Line End found\n");
        
        lineend += len_lineendpattern; // this belongs to the line
        
        linelen = lineend - start; // len of line

        //printf("  mr_getline - linelen=%d\n", linelen);
        
        //printf("  mr_getline - first 7 chars=%.7s [...]\n", start);
        
        *nextchar = lineend;
        
        char* buf = (char*) malloc(linelen + 1);  // needs to be free'd
        if( buf == NULL ){
            *line = NULL;
        }else{
            strncpy(buf, start, linelen);
            buf[linelen] = '\0';

            //printf("  ** mr_getline - complete line found= (see below!)\n%s\n", buf);
            
            *line = buf;
        }
    }
    
    return linelen;
}


/***********************************************************************
 *  main uudecoding functions
 */ 

char* mr_find_uuencoded_part (char* msgtxt, char* lineend){
    /*
     *  find uuencoded part in msgtxt & locate position
     */
     
    char* uu_part_pos = NULL;
    int len_lineend = strlen(lineend);
    
    char tofind[80] = "";
    
    /*
     * blank line is not required for beginning of uuencoded part
     */
    /* strcat(tofind, lineend); */
    strcat(tofind, lineend);
    strcat(tofind, "begin ");
    
    if( (uu_part_pos = strstr(msgtxt, tofind)) ){
        uu_part_pos += len_lineend;
        #ifdef __DEBUG__
        printf("uu found at %d\n", (int)(uu_part_pos - msgtxt));
        #endif
    }
    
    return uu_part_pos;
}


char* mr_handle_uuencoded_part (char* msgtxt, char* uu_msg_start_pos, char* lineend){
    /*
     *  Handle first (!) uuencoded part in a msg
     * 
     * Parameters:
     * 
     *  msgtxt           - is original msg
     *  uu_msg_start_pos - is start position of uuencoded part of msg
     *  lineend          - is pattern of lineend or newline chars
     *
     * Returns:
     *
     *  msgtxt without included uu_part included
     * 
     * Steps:
     * 
     *  1) verify start line and extract filename
     *  2) search for end of uu_part
     *  3) decode uu_part and store it in file
     *       use mr_uudecode() for decoding
     *  4) replace uu_part in original message text by a link to file
     *  5) return changed msg for next loop (one loop handles one uu_part)
     *
     *     If only one uu_part is in msg then next loop will be quick :-)
     */
    
    /*
     *      1) verify start line and extract filename
     */ 
    int   mode;
    char  filename[300] = "";
    char* line = NULL;
    char* nextlinechar = NULL;
    char* uu_body_start;
    char* uu_body_end;
    
    /* build format for first uuencoded line scan*/
    char SSCANF_FORMAT[20] = "begin %o %[^";
    strcat(SSCANF_FORMAT, lineend);
    strcat(SSCANF_FORMAT, "]");
    
    mr_getline(&line, uu_msg_start_pos, lineend, &nextlinechar);
    if(line){  
        sscanf (line, SSCANF_FORMAT, &mode, filename);
        #ifdef __DEBUG__
        printf ("mr_handle_uuencoded_part - mode=%o, filename=%s\n", mode, filename);
        #endif
        free(line);

        if(0 < mode && mode <= 777 && strlen(filename)){
            #ifdef __DEBUG__
            printf ("mr_handle_uuencoded_part - uu_part verified\n");
            #endif
            uu_body_start = nextlinechar;
        }
        else{
            #ifdef __DEBUG__
            printf("mr_handle_uuencoded_part - uu_part not ok, stopping here!\n");
            #endif

            return NULL;
        }
    }
    else
        return NULL;
    
    /*
     *      2) search for end of uu_part
     * 
     *   there are two possible ends defined:
     *     a) with a 'back quote'  and
     *     b) with a 'blank char'       (not handled here!, todo?)
     *
     */
     
    /* build uu end pattern */
    char uu_end[10] = "`";
    strcat(uu_end, lineend);
    strcat(uu_end, "end");
    strcat(uu_end, lineend);
    
    int uu_end_len = strlen(uu_end);

    #ifdef __DEBUG__
    printf("mr_handle_uuencoded_part - uu_end=%s", uu_end);
    #endif
    
    if((uu_body_end = strstr(uu_body_start, uu_end))){
        uu_body_end += uu_end_len;
        #ifdef __DEBUG__
        printf("mr_getline - Line End found, len=%d\n", (int)(uu_body_end - uu_body_start));
        #endif
    }
    else
        return NULL;
    
    
    /*
     *      3) decode uu_part and store it in file
     */
    int uu_body_len = uu_body_end - uu_body_start;
    
    mr_uudecode(uu_body_start, uu_body_len, filename, lineend); 
        /* uudecoded data can be worked here
         *
         * todo (see in mr_uudecode)
         *
         * 1 open file
         * 2 store decoded data in file
         * 3 close it
         * 
         * or do all this into func ????
         */

     
    /*
     *      4) replace uu_part in original message text by a link to file
     */ 

	int len = uu_msg_start_pos - msgtxt;

	// keep first part
    msgtxt[len] = '\0';

	// set link (todo) or remark for message
    sprintf(&msgtxt[len], "\n[uuencoded part cutted here] - filename: %s\n", filename);
    
	// concat remaining part
	strcat(msgtxt, (char*)uu_body_end );
    
    /*
     * 5) return changed msg for next loop (one loop handles one uu_part)
     * 
     */
	return msgtxt;
}



/* Single character decode.  */
#define	DEC(c)	(((c) - ' ') & 077)


void mr_uudecode (char* uuencoded_txt, int uuencoded_txt_len, char* output_filename, char* lineend){
    /*
     *  decode uupart and provide it, used in mrhandle_uuencoded_part
     */
    
    char* line;
    
    int   line_len;
    int   lineend_len = strlen(lineend);
    
    char* nextlinestart = uuencoded_txt;

    // line decoding
    char* p;
    char  ch;
    int   n;
    int   backquote_found = 0;

    #ifdef __DEBUG__
    char s [100] = "";
    char in[100];      // for gets, debugging
    #endif

    /*  decode line by line
     * 
     */
    #ifdef __DEBUG__
    printf("  mr_uudecode - uuencoded_txt_len=%d\n", uuencoded_txt_len);
    #endif
    
    /* open file for output*/
    FILE *fp = fopen(output_filename, "w");
    
    //fputs("This is for testing only. No uuencoded data. Ignore this line!\n", fp);
    #ifdef __DEBUG__
    printf("  mr_uudecode - open file for output=%s\n", output_filename);
    #endif


    /*
     *  do line by line handling
     */
    while( (line_len = mr_getline (&line, nextlinestart, lineend, &nextlinestart)) ){

        /*      Documentation of uuencoded lines
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

        // debug
        #ifdef __DEBUG__
        //printf("  mr_uudecode - line = %s\n", line);
        //gets(in);
        #endif

        /* test for end of uuencoded data */
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
        
        /*      Decode one line 
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
            sprintf(msg, "  mr_uudecode -    *** stopping decoding, invalid line len, N=%d, line_len=%d ***\n", n, (line_len - lineend_len));
            #ifdef __DEBUG__
            puts(msg);
            #endif
            fputs(msg, fp);

            break;
        }
        
        if (n <= 0){
            #ifdef __DEBUG__
            printf("  mr_uudecode -    *** invalid line len %d ***\n", n);
            #endif
            
            break;
        }

        //printf("  mr_uudecode -    n=%d\n", (int)n);
        
        for (++p; n > 0; p += 4, n -= 3){
            if (n >= 3){
                ch = DEC (p[0]) << 2 | DEC (p[1]) >> 4;
                fputc((int)ch, fp);
                
                ch = DEC (p[1]) << 4 | DEC (p[2]) >> 2;
                fputc((int)ch, fp);
                
                ch = DEC (p[2]) << 6 | DEC (p[3]);
                fputc((int)ch, fp);

                //printf("  mr_uudecode -    full block decoded\n");

            }
            else{
                if (n >= 1){
                    ch = DEC (p[0]) << 2 | DEC (p[1]) >> 4;
                    fputc((int)ch, fp);

                    //printf("  mr_uudecode -    n >= 1, n=%d decoded\n", n);
                }
                if (n >= 2){
                    ch = DEC (p[1]) << 4 | DEC (p[2]) >> 2;
                    fputc((int)ch, fp);

                    //printf("  mr_uudecode -    n >= 2, n=%d decoded\n", n);
                }
            }
        }

        free(line);

    }
    #ifdef __DEBUG__
    printf("  mr_uudecode - close file for output=%s\n", output_filename);
    #endif
    fclose(fp);
    
}


char* mr_detect_line_end (char* txt){
    /* detect line end if it is CRLF or LF or CR
     * 
     * this func delivers the first detected line end in a string
     * 
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
    
    return 0;
}


int mr_uu_check_line(int n, int line_len){
    /*
     * checks if n describes the right line len for given encoded char line len
     * 
     * n        = # of encoded bytes
     * line_len = # of chars in encoded string with first len char
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
}




#ifdef __MRUUDECODE_TESTING__

/***********************************************************************
 *
 *  Testing functions 
 *
 ***********************************************************************/


char* ReadFile(char *filename, int* size)
{
    /*
     *  Read a full file in memory 
     */

   char *buffer = NULL;
   int string_size, read_size;
   FILE *handler = fopen(filename, "r");

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

       if (string_size != read_size)
       {
           // Something went wrong, throw away the memory and set
           // the buffer to NULL
           free(buffer);
           buffer = NULL;
       }

       // Always remember to close the file.
       fclose(handler);
    }

    return buffer;
}

/*
 *  Module test 
 */
int main()
{
    int   size    = 0;
    char* lineend = "\r\n";
    char  in[100];
    
    char *string  = ReadFile("WG 1927 Problem geloest - musterdatei-2.eml", &size);
    
    
    //char* s = mr_print_hex(lineend);
    //printf("Test hex = '%s'\n\n", s);
    //free(s);
    
    /*
     * The following code demonstrates using of mr_... functions
     * 
     */
    if (string){
        //puts(string);
        lineend = mr_detect_line_end(string);
        #ifdef __DEBUG__
        printf("Line End = '%s'\n\n", lineend);
        #endif
        char* uustartpos;
        char* source_str = string;
        while(1){
            uustartpos = mr_find_uuencoded_part(source_str, lineend);
            if(uustartpos){
                printf("uu_part found at pos: %.50s [......]\n\n", uustartpos);
                source_str = mr_handle_uuencoded_part (source_str, uustartpos, lineend);
                //printf("printing now message after mr_handle_uuencoded_part\n\n");
                //gets(in);
                //puts("go ....\n\n");
                //puts(r);
            }
            else{
                printf("no or no further uu_part found\n\n");
                printf("printing now message after all mr_handle_uuencoded_part(s)\n\n");
                gets(in);
                puts(source_str);
                break;
            }
        }

        free(string);
        printf("File Size of testing file=%d\n", size);
    }else
        printf("   *** Empty Inputfile ! ***\n");

  
  return 0;
}

#endif /* __MRUUDECODE_TESTING__ */
