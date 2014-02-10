#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>

#include "islib.h"
#include "iwcrypto.h"

/*---------------------------------------------------------------------------*/
/* グローバル定数定義                                                        */
/*---------------------------------------------------------------------------*/
#define READ_BUF_SIZE    4096

/*---------------------------------------------------------------------------*/
/* 暗号化キー                                                        */
/*---------------------------------------------------------------------------*/
#define CRYPTOKEY "ygHxXW7Y+LiQDz7YUyIh4I9Ig28X6VaYAHMmFIXGEnJXEAXx7hGQgY"

/*---------------------------------------------------------------------------*/
/* グローバル変数定義                                                        */
/*---------------------------------------------------------------------------*/
static char s_efile[512];       /* エラーログファイル名     */
static char s_afile[512];       /* アクセスログファイル名   */
static char s_tfile[512];       /* トレースログファイル名   */
static int  s_elevel;           /* エラーログレベル         */
static int  s_alevel;           /* アクセスログレベル       */
static int  s_tlevel;           /* トレースログレベル       */

/*---------------------------------------------------------------------------*/
/*1 機能概要: ログ初期化関数                                                 */
/*2 呼出形式: void Isl_LogInit( e_file, e_level, a_file, a_level, t_file, t_level ) */
/*3 戻り情報:                                                                */
/*3:     正常終了                                                            */
/*5 制限事項:                                                                */
/*5:    ログファイルのファイル名は最大511文字まで。                          */
/*6 機能説明:                                                                */
/*6:    ログファイル名、ログ出力レベルをセットする。                         */
/*6:      ◇ エラーログ                                                      */
/*6:      ◇ アクセスログ                                                    */
/*6:      ◇ トレースログ                                                    */
/*6:                                                                         */
/*---------------------------------------------------------------------------*/
void Isl_LogInit( e_file, e_level, a_file, a_level, t_file, t_level )
char *e_file;       /*i エラーログファイル名    */
int  e_level;       /*i エラーログレベル        */
char *a_file;       /*i アクセスログファイル名  */
int  a_level;       /*i アクセスログレベル      */
char *t_file;       /*i トレースログファイル    */
int  t_level;       /*i トレースログレベル      */
{
    /* エラーログファイル   */
	if ( e_file != NULL ) {
    	strncpy( s_efile, e_file, 511 );
	}
    s_elevel = e_level;
    
    /* アクセスログファイル */
	if ( a_file != NULL ) {
    	strncpy( s_afile, a_file, 511 );
	}
    s_alevel = a_level;
    
    /* トレースログファイル */
	if ( t_file != NULL ) {
    	strncpy( s_tfile, t_file, 511 );
	}
    s_tlevel = t_level;
}

/*---------------------------------------------------------------------------*/
/*1 機能概要: トレースログ出力関数                                           */
/*2 呼出形式: void Isl_LogTrace( int level, char *logmsg, ... )              */
/*3 戻り情報:                                                                */
/*3:     正常終了                                                            */
/*5 制限事項:                                                                */
/*5:    なし                                                                 */
/*6 機能説明:                                                                */
/*6:    1.  LogFile を開く                                                   */
/*6:    2.  引数で与えられたデータと時間をLogFileに、書きこむ                */
/*6:    3.  LogFile を閉じる                                                 */
/*---------------------------------------------------------------------------*/
void Isl_LogTrace( int level, char *logmsg, ... )
{
    va_list  w_arg;
    int      w_fd;
    int      w_err;
    pid_t    w_pid;
    FILE     *w_fp;
    struct   tm      w_tm;
    struct   timeval w_tval;

    /* Logレベル判定 */
    if ( !(level & s_tlevel) ) {
        return;
    }
    
    /* LogFile を開く ( 無かった場合は、LogFileを作成する ) */
    /* 失敗した場合には何もせず終了                         */
    w_fd = open( s_tfile, O_WRONLY | O_CREAT | O_APPEND, 0666 );
    if ( w_fd  <= 0 ) {
        return;
    }
    
    /* ファイルのロック                                     */
    /* ロックに失敗した場合には、ファイルを閉じて終了       */
    w_err = lockf( w_fd, F_LOCK, 0 );
    if ( w_err !=  0 ) {
        return;
    }

    /* ファイルデスクリプタをファイルポインタに付け替え     */
    /* 失敗した場合には、ファイルを閉じて終了               */
    w_fp = fdopen( w_fd, "a" );
    if( w_fp == NULL ) {
        lockf( w_fd, F_ULOCK, 0 );
        close( w_fd );
        return;
    }

    /* 現在時刻の取得                                       */
    /* 失敗した場合には、ファイルを閉じて終了               */
    w_err = gettimeofday( &w_tval, NULL );
    if ( w_err != 0 ) {
        lockf( w_fd, F_ULOCK, 0 );
        close( w_fd );
        return;
    }
    
    /* 時間の書き込み */
    localtime_r( &(w_tval.tv_sec), &w_tm );
    fprintf( w_fp, "[%04d/%02d/%02d %02d:%02d:%02d.%04d] ",
        w_tm.tm_year + 1900, w_tm.tm_mon + 1, w_tm.tm_mday,
        w_tm.tm_hour, w_tm.tm_min, w_tm.tm_sec, w_tval.tv_usec/100 );

    /* pidの書き込み */
    w_pid = getpid();
    fprintf( w_fp, "(%d) ", w_pid );
    
    /* メッセージの書き出し */
    va_start( w_arg, logmsg );
    vfprintf( w_fp, logmsg, w_arg );
    va_end( w_arg );

    /* LogFile を閉じる */
    lockf( w_fd, F_ULOCK, 0 );
    fclose( w_fp );

    return;
}

/*---------------------------------------------------------------------------*/
/*1 機能概要: アクセスログ出力関数                                           */
/*2 呼出形式: void Isl_LogAccess( int level, char *logmsg, ... )             */
/*3 戻り情報:                                                                */
/*3:     正常終了                                                            */
/*5 制限事項:                                                                */
/*5:    なし                                                                 */
/*6 機能説明:                                                                */
/*6:    1.  LogFile を開く                                                   */
/*6:    2.  引数で与えられたデータと時間をLogFileに、書きこむ                */
/*6:    3.  LogFile を閉じる                                                 */
/*---------------------------------------------------------------------------*/
void Isl_LogAccess( int level, char *logmsg, ... )
{
    va_list  w_arg;
    int      w_fd;
    int      w_err;
    FILE     *w_fp;
    struct   tm      w_tm;
    struct   timeval w_tval;

    /* Logレベル判定 */
    if ( level > s_alevel ) {
        return;
    }
    
    /* LogFile を開く ( 無かった場合は、LogFileを作成する ) */
    /* 失敗した場合には何もせず終了                         */
    w_fd = open( s_afile, O_WRONLY | O_CREAT | O_APPEND, 0666 );
    if ( w_fd  <= 0 ) {
        return;
    }
    
    /* ファイルのロック                                     */
    /* ロックに失敗した場合には、ファイルを閉じて終了       */
    w_err = lockf( w_fd, F_LOCK, 0 );
    if ( w_err !=  0 ) {
        return;
    }

    /* ファイルデスクリプタをファイルポインタに付け替え     */
    /* 失敗した場合には、ファイルを閉じて終了               */
    w_fp = fdopen( w_fd, "a" );
    if( w_fp == NULL ) {
        lockf( w_fd, F_ULOCK, 0 );
        close( w_fd );
        return;
    }

    /* 現在時刻の取得                                       */
    /* 失敗した場合には、ファイルを閉じて終了               */
    w_err = gettimeofday( &w_tval, NULL );
    if ( w_err != 0 ) {
        lockf( w_fd, F_ULOCK, 0 );
        close( w_fd );
        return;
    }
    
    /* 時間の書き込み */
    localtime_r( &(w_tval.tv_sec), &w_tm );
    fprintf( w_fp, "[%04d/%02d/%02d %02d:%02d:%02d] ",
        w_tm.tm_year + 1900, w_tm.tm_mon + 1, w_tm.tm_mday,
        w_tm.tm_hour, w_tm.tm_min, w_tm.tm_sec );

    /* メッセージの書き出し */
    va_start( w_arg, logmsg );
    vfprintf( w_fp, logmsg, w_arg );
    va_end( w_arg );

    /* LogFile を閉じる */
    lockf( w_fd, F_ULOCK, 0 );
    fclose( w_fp );

    return;
}

/*---------------------------------------------------------------------------*/
/*1 機能概要: エラーログ出力関数                                             */
/*2 呼出形式: void Isl_LogError( int level, char *logmsg, ... )              */
/*3 戻り情報:                                                                */
/*3:     正常終了                                                            */
/*5 制限事項:                                                                */
/*5:    なし                                                                 */
/*6 機能説明:                                                                */
/*6:    1.  LogFile を開く                                                   */
/*6:    2.  引数で与えられたデータと時間をLogFileに、書きこむ                */
/*6:    3.  LogFile を閉じる                                                 */
/*---------------------------------------------------------------------------*/
void Isl_LogError( int level, char *logmsg, ... )
{
    va_list  w_arg;
    int      w_fd;
    int      w_err;
    pid_t    w_pid;
    FILE     *w_fp;
    struct   tm      w_tm;
    struct   timeval w_tval;

    /* Logレベル判定 */
    if ( level > s_elevel ) {
        return;
    }
    
    /* LogFile を開く ( 無かった場合は、LogFileを作成する ) */
    /* 失敗した場合には何もせず終了                         */
    w_fd = open( s_efile, O_WRONLY | O_CREAT | O_APPEND, 0666 );
    if ( w_fd  <= 0 ) {
        return;
    }
    
    /* ファイルのロック                                     */
    /* ロックに失敗した場合には、ファイルを閉じて終了       */
    w_err = lockf( w_fd, F_LOCK, 0 );
    if ( w_err !=  0 ) {
        return;
    }

    /* ファイルデスクリプタをファイルポインタに付け替え     */
    /* 失敗した場合には、ファイルを閉じて終了               */
    w_fp = fdopen( w_fd, "a" );
    if( w_fp == NULL ) {
        lockf( w_fd, F_ULOCK, 0 );
        close( w_fd );
        return;
    }

    /* 現在時刻の取得                                       */
    /* 失敗した場合には、ファイルを閉じて終了               */
    w_err = gettimeofday( &w_tval, NULL );
    if ( w_err != 0 ) {
        lockf( w_fd, F_ULOCK, 0 );
        close( w_fd );
        return;
    }
    
    /* 時間の書き込み */
    localtime_r( &(w_tval.tv_sec), &w_tm );
    fprintf( w_fp, "[%04d/%02d/%02d %02d:%02d:%02d.%04d] ",
        w_tm.tm_year + 1900, w_tm.tm_mon + 1, w_tm.tm_mday,
        w_tm.tm_hour, w_tm.tm_min, w_tm.tm_sec, w_tval.tv_usec/100 );

    /* pidの書き込み */
    w_pid = getpid();
    fprintf( w_fp, "(%d) ", w_pid );
    
    /* エラーレベルの書き込み */
    switch ( level ) {
        case ISL_LOG_FATAL:
            fprintf( w_fp, "Fatal: " );
            break;
            
        case ISL_LOG_WARNING:
            fprintf( w_fp, "Warning: " );
            break;

        case ISL_LOG_INFO:
            fprintf( w_fp, "Info: " );
            break;
    }
    
    /* メッセージの書き出し */
    va_start( w_arg, logmsg );
    vfprintf( w_fp, logmsg, w_arg );
    va_end( w_arg );

    /* LogFile を閉じる */
    lockf( w_fd, F_ULOCK, 0 );
    fclose( w_fp );

    return;
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  バッファ構造体領域作成関数                                    */
/*2 呼出形式:  ISL_BUFFER *Isl_Buf_Create( alloc_size )                      */
/*3 戻り情報:                                                                */
/*3:    NULL以外: ISL_BUFFER構造体のポインタアドレス                         */
/*3:    NULL    : 異常終了                                                   */
/*5 制限事項:                                                                */
/*5:    領域作成後は必ずIsl_Buf_Release関数で領域を開放しなければならない    */
/*6 機能説明:                                                                */
/*6:                                                                         */
/*6:    ISL_BUFFER構造体をmallocして構造体をNULLクリア                       */
/*6:    パラメータのアロケートサイズを構造体のalloc_sizeメンバに設定         */
/*6:    戻り値がNULLの場合はmallocエラーが発生したことを示す                 */
/*6:                                                                         */
/*---------------------------------------------------------------------------*/
ISL_BUFFER *Isl_Buf_Create( alloc_size )
int    alloc_size;    /* アロケートサイズ */
{
    ISL_BUFFER    *w_stbuf;

    /* パラメータチェック */
    if( alloc_size == 0 ){
        w_stbuf = NULL;
    } else {
        /* バッファ構造体領域確保 */
        w_stbuf = ( ISL_BUFFER *)malloc( sizeof( ISL_BUFFER ));
        if( w_stbuf == NULL ){
            /* 明示的にNULLをセット */
            w_stbuf = NULL;
        } else {
            /* バッファ構造体の初期化 */
            memset( w_stbuf, 0x00, sizeof( ISL_BUFFER ));
            w_stbuf->alloc_size = alloc_size;
        }
    }
    return( w_stbuf );
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  バッファ構造体領域開放関数                                    */
/*2 呼出形式:  int Isl_Buf_Release( st_buf )                                 */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS : 正常終了                                               */
/*3:    ISL_ERROR   : 異常終了                                               */
/*5 制限事項:                                                                */
/*5:    Isl_Buf_Create関数でバッファ構造体が作成されている必要がある         */
/*5:    Isl_Buf_Create関数でバッファ構造体作成後かならず実行する必要がある   */
/*6 機能説明:                                                                */
/*6:    バッファ構造体領域を開放する                                         */
/*---------------------------------------------------------------------------*/
int Isl_Buf_Release( st_buf )
ISL_BUFFER *st_buf;    /*i 開放対象バッファ構造体   */
{
    int w_result;    /* リターンコード */

    if( st_buf == NULL ){
        w_result = ISL_SUCCESS;
    } else {
        if( st_buf->buffer != NULL ){
            free( st_buf->buffer );
            st_buf->buffer = NULL;
        }
        free( st_buf );
        st_buf = NULL;
        w_result = ISL_SUCCESS;
    }

    return( w_result );
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  バッファ追加書き込み関数                                      */
/*2 呼出形式:  int Isl_Buf_AddBuf( st_buf, buffer, buf_len )                 */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS : 正常終了                                               */
/*3:    ISL_ERROR   : 異常終了                                               */
/*5 制限事項:                                                                */
/*5:    Isl_Buf_Create関数でバッファ構造体が作成されている必要がある         */
/*5:    第3パラメータのbuf_lenはゼロ以上の数値である必要がある               */
/*5:    ゼロの場合は何もせずに終了する。構造体がNULLの場合も同様。           */
/*6 機能説明:                                                                */
/*6:    bufferをst_buf構造体に設定する。すでに設定済みの場合は追記する。     */
/*---------------------------------------------------------------------------*/
int Isl_Buf_AddBuf( st_buf, buffer, buf_len )
ISL_BUFFER *st_buf;      /*x バッファ書き込み用バッファ構造体   */
char       *buffer;      /*i バッファ構造体に書き込むバッファ   */
int         buf_len;     /*i バッファ構造体に書き込むバッファ長 */
{
    int    w_result;  /* リターンコード                     */ 
    int    w_newlen;  /* 追加書き込み分を踏まえたバッファ長 */
    int    w_size;    /* 新バッファ領域(malloc)長           */
    char  *w_wrkbuf;  /* バッファポインタ編集用ポインタ     */

    /* パラメータチェック */
    if( st_buf == NULL || buf_len == 0 ){
        /* 何もしないで終了 */
        w_result = ISL_SUCCESS;
    } else {
        w_newlen = st_buf->buf_len + buf_len;
        /* 現在のバッファサイズと今回必要なバッファ長を比較 */
        if( st_buf->buf_size < w_newlen ){
            /* alloc_sizeの倍数でバッファサイズを確保するための式 */
            w_size = ( w_newlen / st_buf->alloc_size + 1 ) * st_buf->alloc_size;
            if( Isl_Alloc( &st_buf->buffer, st_buf->buf_size, w_size, 0x00 ) == ISL_ERROR ){
                w_result = ISL_ERROR;
            } else {
                /* strcatを使わず直接編集するためポインタ計算 */
                w_wrkbuf = st_buf->buffer + st_buf->buf_len;
                memcpy( w_wrkbuf, buffer, buf_len );
                /* バッファサイズ(malloc長)を変更 */
                st_buf->buf_size = w_size;
                st_buf->buf_len = w_newlen;
                w_result = ISL_SUCCESS;
            }
        } else {
            /* strcatを使わず直接編集するためポインタ計算 */
            w_wrkbuf = st_buf->buffer + st_buf->buf_len;
            memcpy( w_wrkbuf, buffer, buf_len );
            /* バッファサイズを変更せずに追記 */
            st_buf->buf_len = w_newlen;
            w_result = ISL_SUCCESS;
        }
    }
    return( w_result );
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  バッファ上書き関数                                            */
/*2 呼出形式:  int Isl_Buf_SetBuf( st_buf, buffer, buf_len )                 */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS : 正常終了                                               */
/*3:    ISL_ERROR   : 異常終了                                               */
/*5 制限事項:                                                                */
/*5:    Isl_Buf_Create関数でバッファ構造体が作成されている必要がある         */
/*5:    第3パラメータのbuf_lenはゼロ以上の数値である必要がある               */
/*5:    ゼロの場合は何もせずに終了する。構造体がNULLの場合も同様。           */
/*6 機能説明:                                                                */
/*6:    bufferをst_buf構造体に設定する。すでに設定済みの場合は上書きする。   */
/*---------------------------------------------------------------------------*/
int Isl_Buf_SetBuf( st_buf, buffer, buf_len )
ISL_BUFFER *st_buf;      /*x バッファ書き込み用バッファ構造体   */
char       *buffer;      /*i バッファ構造体に書き込むバッファ   */
int         buf_len;     /*i バッファ構造体に書き込むバッファ長 */
{
    int    w_result;
    int    w_size;

    /* パラメータチェック */
    if( st_buf == NULL || buf_len == 0 ){
        /* 何もしないで終了 */
        w_result = ISL_SUCCESS;
    } else {
        /* 現在のバッファサイズと今回のデータ長を比較 */
        if( st_buf->buf_size < buf_len ){
            /* alloc_sizeの倍数でバッファ領域を確保するための式 */
            w_size = ( buf_len / st_buf->alloc_size + 1 ) * st_buf->alloc_size;
            /* アロケート関数でリサイズ */
            if( Isl_Alloc( &st_buf->buffer, st_buf->buf_size, w_size, 0x00 ) == ISL_ERROR ){
                w_result = ISL_ERROR;
            } else {
                /* バッファサイズ(malloc長)を変更 */ 
                memset( st_buf->buffer, 0x00, w_size );
                st_buf->buf_size = w_size;
                memcpy( st_buf->buffer, buffer, buf_len );
                st_buf->buf_len = buf_len;
                w_result = ISL_SUCCESS;
            }
        } else {
            /* バッファサイズを変更せずに書き込み */
            memset( st_buf->buffer, 0x00, st_buf->buf_size );
            memcpy( st_buf->buffer, buffer, buf_len );
            st_buf->buf_len = buf_len;
            w_result = ISL_SUCCESS;
        }
    }

    return( w_result );
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  バッファ情報取得関数                                          */
/*2 呼出形式:  char *Isl_Buf_GetBuf( st_buf )                                */
/*3 戻り情報:                                                                */
/*3:    NULL以外 : charのポインタアドレス                                    */
/*3:    NULL     : 異常終了                                                  */
/*5 制限事項:                                                                */
/*5:    Isl_Buf_Create関数でバッファ構造体が作成されている必要がある。       */
/*5:    この関数で取得した値を編集すると構造体内部が壊れます。               */
/*5:    このため戻り値は参照のみ利用可能とする。                             */
/*5:    編集が必要な場合はSetBuf関数かAddBuf関数を利用すること。             */
/*6 機能説明:                                                                */
/*6:    バッファ構造体からバッファを取得する                                 */
/*---------------------------------------------------------------------------*/
char *Isl_Buf_GetBuf( st_buf )
ISL_BUFFER *st_buf;    /*i バッファ情報取得用バッファ構造体   */
{
    if( st_buf == NULL ){
        return( NULL );
    } else {
        return( st_buf->buffer );
    }
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  アロケート関数                                                */
/*2 呼出形式:  int Isl_Alloc( buffer, buf_size, alloc_size, ch_ini )         */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS : 正常終了                                               */
/*3:    ISL_ERROR   : 異常終了                                               */
/*5 制限事項:                                                                */
/*5:    buf_sizeが0の場合は新規アロケートとする。                            */
/*6 機能説明:                                                                */
/*6:  第3パラメータで第1パラメータをアロケートし、第4パラメータで初期化する。*/
/*6:  すでにアロケート済みの場合(第2パラメータで判断)はアロケートしなおす。  */
/*6:  このとき、元のバッファ情報を新アロケートサイズ分まで引き継ぐ。         */
/*6:  (新サイズが元より小さい場合は元の途中までデータを格納し、              */
/*6:                大きい場合は後ろ部分が全て第4パラメータで埋め尽くされる) */
/*---------------------------------------------------------------------------*/
int Isl_Alloc( buffer, buf_size, alloc_size, ch_ini )
char **buffer;      /* アロケート対象ポインタのポインタアドレス */
int    buf_size;    /* 現在のアロケートサイズ(新規の場合は0)    */
int    alloc_size;  /* アロケートサイズ                         */
int    ch_ini;      /* 初期化変数(基本は0x00)                   */
{
    char *w_newbuf;      /* ニューバッファ     */
    int   w_result;      /* リターンコード     */

    /* パラメータチェック */
    if( alloc_size == 0 ){
        w_result = ISL_ERROR;
    } else {
        /* アロケートパターンチェック */
        if( buf_size == 0 && *buffer == NULL ){
            /* 新規アロケート処理 */
            *buffer = ( char *)malloc( alloc_size );
            if( *buffer == NULL ){
                /* 明示的にNULLセット */
                *buffer = NULL;
                w_result = ISL_ERROR;
            } else {
                /* 初期化 */
                memset( *buffer, ch_ini, alloc_size );
                w_result = ISL_SUCCESS;
            }
        } else {
            /* 拡張/縮小などのリアロケート処理 */
            if( *buffer == NULL ){
                w_result = ISL_ERROR;
            } else { 
                w_newbuf = ( char *)malloc( alloc_size );
                if( w_newbuf == NULL ){
                    /* 明示的にNULLセット */
                    w_newbuf = NULL;
                    w_result = ISL_ERROR;
                } else {
                    if( buf_size == 0 ){
                        /* 初期化 */
                        memset( w_newbuf, ch_ini, alloc_size );
                    } else {
                        /* 初期化と元バッファのコピー */
                        memset( w_newbuf, ch_ini, alloc_size );
                        memcpy( w_newbuf, *buffer, buf_size );
                    }
                    /* ポインタ書き換え */
                    free( *buffer );
                    *buffer = w_newbuf;
                    w_result = ISL_SUCCESS;
                } 
            }
        }
    }
    return( w_result );
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  フリー関数                                                    */
/*2 呼出形式:  int Isl_Free( buffer )                                        */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS : 正常終了                                               */
/*3:    ISL_ERROR   : 異常終了                                               */
/*5 制限事項:                                                                */
/*5:    void型でも問題ないぐらい正常終了しか返さない                         */
/*6 機能説明:                                                                */
/*6:    NULLチェック後freeしNULLを設定する                                   */
/*---------------------------------------------------------------------------*/
int Isl_Free( buffer )
char **buffer;      /* フリー対象ポインタのポインタアドレス */
{
    int   w_result; /* リターンコード */

    if( *buffer == NULL ){
        w_result = ISL_SUCCESS;
    } else {
        free( *buffer );
        *buffer = NULL;
        w_result = ISL_SUCCESS;
    }
    return( w_result );
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  NAME/VALUEの管理構造体作成関数                                */
/*2 呼出形式:  int Isl_ConfigRead( nameval, filename )                       */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS   : 正常終了                                             */
/*3:    ISL_ERR_NOMEM : メモリ不足                                           */
/*3:    ISL_ERR_FOPEN : コンフィグファイルオープンエラー                     */
/*5 制限事項:                                                                */
/*5:    パラメータのnamevalは、Isl_NameValue_Create()で作成されていること。  */
/*6 機能説明:                                                                */
/*6:                                                                         */
/*6:    ISL_NAMEVALUE構造体をmallocして構造体をNULLクリア                    */
/*6:                                                                         */
/*---------------------------------------------------------------------------*/
int Isl_ConfigRead( nameval, filename )
ISL_NAMEVALUE *nameval;     /*x コンフィグデータの格納場所 */
char          *filename;    /*i コンフィグファイル名       */
{
    int  w_err;
    FILE *w_fp;
    char w_read_buf[READ_BUF_SIZE];
    char *w_name, *w_value, *w_ptr, *w_read_ptr;
    
    /* コンフィグファイルオープン */
    if ( ( w_fp = fopen( filename, "r") ) == NULL ) {
        return( ISL_ERR_FOPEN );
    }
    
    /* コンフィグファイルを読み込んで、ISL_NAMEVALUE */
    /* 構造体にセットする。                          */
    w_err = ISL_SUCCESS;
    while( 1 ) {
        w_read_ptr = fgets( w_read_buf, READ_BUF_SIZE, w_fp );
        if ( w_read_ptr == NULL ) {
            /* ファイルの終わりに来たら終了 */
            break;
        }
        
        /* 空白行は読み飛ばし */
        if ( strlen( w_read_buf ) == 0 ) {
            continue;
        }
        
        /* コメント行は読み飛ばし */
        if ( w_read_buf[0] == '#' ) {
            continue;
        }
        
        /* 読んだ1行の'='の前を取得 (NAMEになる) */
        /* NAMEがNULLはありえないので無視する。  */
        w_name = (char *)strtok_r( w_read_buf, "=", &w_ptr );
        if ( w_name == NULL ) {
            continue;
        }
        
        /* 読んだ1行の'='の後ろを取得 (VALUEになる)  */
        /* VALUEがNULLなのはありだからチェックしない */
        w_value = (char *)strtok_r( NULL, "\r\n", &w_ptr );
        
        /* NAME/VALUEをISL_NAMEVALUEにセット */
        w_err = Isl_NameValue_Add( nameval, w_name, w_value );
        if ( w_err != ISL_SUCCESS ) {
            /* ここでw_err!=ISL_SUCCESSなのはISL_NOMENの時    */
            /* メモリが無いのに処理を続けてもしょうがないので */
            /* やめてしまえ！                                 */
            break;
        }
    }
    
    fclose( w_fp );
    
    /* w_errがISL_SUCCESS以外になるのは、Isl_NameValue_Add()に */
    /* 失敗したときのみ                                        */
    return( w_err );
}

/*---------------------------------------------------------------------------*/
/*1 機能概:  NAME/VALUEの管理構造体作成関数                                  */
/*2 呼出形式:  ISL_NAMEVALUE *Isl_NameValue_Create()                         */
/*3 戻り情報:                                                                */
/*3:    NULL以外: ISL_NAMEVALUE構造体へのポインタ                            */
/*3:    NULL    : malloc()エラー                                             */
/*5 制限事項:                                                                */
/*5:    ISL_NAMEVALUE構造体を使う場合には、この関数を必ず呼ぶこと            */
/*6 機能説明:                                                                */
/*6:                                                                         */
/*6:    ISL_NAMEVALUE構造体をmallocして構造体をNULLクリア                    */
/*6:                                                                         */
/*---------------------------------------------------------------------------*/
ISL_NAMEVALUE *Isl_NameValue_Create()
{
    ISL_NAMEVALUE *w_nameval;
    
    w_nameval = (ISL_NAMEVALUE *)malloc( sizeof(ISL_NAMEVALUE) );
    if ( w_nameval == NULL ) {
        return( NULL );
    }
    memset( w_nameval, 0x00, sizeof(ISL_NAMEVALUE) );
    
    return( w_nameval );
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  NAME/VALUEの管理構造体開放関数                                */
/*2 呼出形式:  int *Isl_NameValue_Release()                                  */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS : 正常終了                                               */
/*5 制限事項:                                                                */
/*5:    Isl_NameValue_Create()関数で作成されてないアドレスをパラメータに指定 */
/*5:    したり、同じパラメータを指定して２度実行してはならない。             */
/*6 機能説明:                                                                */
/*6:                                                                         */
/*6:                                                                         */
/*---------------------------------------------------------------------------*/
int  Isl_NameValue_Release( nameval )
ISL_NAMEVALUE *nameval;     /*i 開放するISL_NAMEVALU構造体のアドレス */
{
    ISL_NAMEVAL_ELEMENT *w_elem;

    /* アドレスがNULLならそのまま戻る */
    if ( nameval == NULL ) {
        return( ISL_SUCCESS );
    }
    
    /* NAME/VALUの要素を全てfreeする */
    while( nameval->first != NULL ) {
        w_elem = nameval->first->next;
        free( nameval->first );
        nameval->first = w_elem;
    }
    
    /* NAME/VALUEの管理構造体自身をfreeする */
    free( nameval );
    
    return( ISL_SUCCESS );
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  NAME/VALUE形式の値を追加する関数                              */
/*2 呼出形式:  int *Isl_NameValue_Add()                                      */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS   : 正常終了                                             */
/*3:    ISL_ERR_NOMEM : メモリ不足 (mallocエラー)                            */
/*5 制限事項:                                                                */
/*5:    パラメータで指定するのは、Isl_NameValue_Create()関数で作成された     */
/*5:    ISL_NAMEVALUE構造体であること。                                      */
/*6 機能説明:                                                                */
/*6:                                                                         */
/*6:                                                                         */
/*---------------------------------------------------------------------------*/
int  Isl_NameValue_Add( nameval, name, value )
ISL_NAMEVALUE *nameval;
char          *name;
char          *value;
{
    ISL_NAMEVAL_ELEMENT *w_elem;
    
    /* NAME/VALUEの要素をmalloc */
    w_elem = (ISL_NAMEVAL_ELEMENT *)malloc( sizeof(ISL_NAMEVAL_ELEMENT) );
    if ( w_elem == NULL ) {
        return( ISL_ERR_NOMEM );
    }
    
    /* NAMEのmallocと値のセット */
    w_elem->name = (char *)malloc( strlen(name) + 1 );
    if ( w_elem->name == NULL ) {
        free( w_elem );
        return( ISL_ERR_NOMEM );
    }
    strcpy( w_elem->name, name );
    
    /* VALUEのmallocと値のセット */
    /* VALUE値がNULLだったらそのままNULLをセット */
    if ( value != NULL ) {
        w_elem->value = (char *)malloc( strlen(value) + 1 );
        if ( w_elem->value == NULL ) {
            free( w_elem->name );
            free( w_elem );
            return( ISL_ERR_NOMEM );
        }
        strcpy( w_elem->value, value );
    } else {
        w_elem->value = NULL;
    }
    
    /* 管理構造体の要素数をインクリメント */
    nameval->count++;
    
    /* 最初の要素を追加するときは管理構造体のメンバも初期化 */
    if ( nameval->first == NULL ) {
        w_elem->next   = NULL;
        w_elem->prev   = NULL;
        nameval->first = w_elem;
        nameval->last  = w_elem;
    } else {
        /* NAME/VALUEの要素をISL_NAMEVALUE構造体に追加 */
        w_elem->next       = NULL;
        w_elem->prev       = nameval->last;
        w_elem->prev->next = w_elem;
        nameval->last      = w_elem;
    }
    
    return( ISL_SUCCESS );
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  NAMEの検索                                                    */
/*2 呼出形式:  char *Isl_NameValue_GetValue( nameval, name )                 */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS : 正常終了                                               */
/*5 制限事項:                                                                */
/*5:    検索結果が見つからなくてもNULL。元々のvalueがNULLでもNULL。          */
/*5:    戻り値からはそれぞれの判断ができない。                               */
/*6 機能説明:                                                                */
/*6:                                                                         */
/*6:                                                                         */
/*---------------------------------------------------------------------------*/
char *Isl_NameValue_GetValue( nameval, name )
ISL_NAMEVALUE *nameval;     /*i 検索する対象     */
char          *name;        /*i キーとなる文字列 */
{
    ISL_NAMEVAL_ELEMENT *w_elem;
    
    /* リストの最後まで検索 */
    w_elem = nameval->first;
    while ( w_elem ) {
        /* 検索データが見つかったら終了 */
        if ( strcasecmp( w_elem->name, name ) == 0 ) {
            break;
        }
        
        w_elem = w_elem->next;
    }
    
    /* 検索結果が見つかればその値を返す。     */
    /* 検索結果が見つからなければNULLを返す。 */
    if ( w_elem == NULL ) {
        return( NULL );
    } else {
        return( w_elem->value );
    }
}

/*---------------------------------------------------------------------------*/
/*1 機能概要:  文字列の最初がNAMEと一致するものの検索                        */
/*2 呼出形式:  char *Isl_NameValue_ALLGetVal( nameval, name ,number )        */
/*3 戻り情報:                                                                */
/*3:    ISL_SUCCESS : 正常終了                                               */
/*5 制限事項:                                                                */
/*5:    検索結果が見つからなくてもNULL。元々のvalueがNULLでもNULL。          */
/*5:    戻り値からはそれぞれの判断ができない。                               */
/*6 機能説明:                                                                */
/*6:    検索はリストのnumber番目から開始する。                               */
/*6:    一致した場合、ポインタnumberに一致した次の番目の数字が入り戻る       */
/*6:                                                                         */
/*---------------------------------------------------------------------------*/
char *Isl_NameValue_ALLGetVal(nameval, name, number)
ISL_NAMEVALUE *nameval; /* 検索する対象                       */
char          *name;   /* キーとなる文字列                   */
int           *number;  /* リストの何番目から検索を開始するか */
{
    int w_result;
    int kaunta=1;                   /* カウンタ               */
    ISL_NAMEVAL_ELEMENT *w_elem;

    /* リストの一番目を読む */
    w_elem = nameval->first;

    /* *numberの値までリストが進んだらループ脱出。リストが最後まで行ってもループ脱出 */
    while ( w_elem ) {
        if( kaunta == *number ){
            kaunta++;
            break;
      }
        w_elem = w_elem->next;
        kaunta++;
    }

    /* nameの文字列数を所得（strncasecmp使用のために必要） */
    w_result = strlen(name);

    /* リストの最後まで検索 */
    while ( w_elem ) {
        /* 検索データが見つかったら終了 */
        if ( strncasecmp( w_elem->name, name, w_result ) == 0 ) {
            break;
        }

        w_elem = w_elem->next;
        *number = *number+1;
    }
        *number = *number+1;

    /* 検索結果が見つかればその値を返す。    */
    /* 検索結果が見つからなければNULLを返す。 */
    if ( w_elem == NULL ) {
        return( NULL );
    } else {
        return( w_elem->value );
    }
}

/*****************************************************************************/
/*1 機能概要: POSTデータデコード処理モジュール                               */
/*2 呼出形式: char *Isl_Url_Decode( postdata )                               */
/*3 戻り情報:                                                                */
/*3   NULL以外 : デコード後POSTデータのアドレス                              */
/*3   NULL     : 異常終了                                                    */
/*5 制限事項:                                                                */
/*5   postdataはNULLストップ文字列であることとする                           */
/*5   戻り値は使用後free()すること                                           */
/*6 機能説明:                                                                */
/*6   url-encodeされているPOSTデータをShift-JISへデコードする                */
/*****************************************************************************/
char *Isl_Url_Decode( postdata)
char *postdata;
{
    char *w_encode_post;          /* デコード前POSTデータ */
    char *w_decode_post;          /* デコード後POSTデータ */
    char w_work_char[3];          /* デコード作業用配列   */
    int w_index;
    int w_arg_index;
    int w_work_int;
    int w_length;

    /* 領域の確保・POSTデータ設定 */
    w_index = 0;
    w_arg_index = 0;
    w_length = strlen( postdata );
    w_decode_post = ( char *)malloc( w_length + 1 );
    w_encode_post = ( char *)malloc( w_length + 1 );
    memset( w_decode_post, '\0', w_length + 1 );
    memset( w_encode_post, '\0', w_length + 1 );
    memcpy( w_encode_post, postdata, w_length );

    while( 1 ) {
        if( w_encode_post[w_index] == '\0' ) {
            /* \0がきたら終了 */
            break;
        } else {
            if( w_encode_post[ w_index ] == '%') {

                /* %がきたらデコード処理開始 */
                if( w_encode_post[ w_index + 1] == '\0' || w_encode_post[w_index + 2] == '\0' ) {
                    /* エンコード文字列中に\0が存在すれば終了 */
                    w_decode_post[ w_arg_index++ ] = w_encode_post[ w_index ];
                    break;
                }

                /* %以降のエンコードされた値の取得 */
                strncpy( w_work_char, &( w_encode_post[ w_index + 1 ]), 2 );
                w_work_char[2] = '\0';

                /* 値を10進に変換 */
                sscanf( w_work_char, "%X", &w_work_int );

                /* デコード結果を格納 */
                w_decode_post[ w_arg_index++ ] = ( char )w_work_int;
                w_index = w_index + 2;

            } else {
                if( w_encode_post[w_index] == '&' ) {

                    /* &がきたら空白に変換 */
/*                    w_decode_post[ w_arg_index++ ] = '\t'; */
                    w_decode_post[ w_arg_index++ ] = ' '; 
                } else {
                    if( w_encode_post[w_index] == '+' ) {

                        /* +がきたら空白に変換 */
                        w_decode_post[ w_arg_index++ ] = ' ';
                    } else {

                        /* ここに来た時点で変換対象ではないので、なにもしない */
                        w_decode_post[w_arg_index++] = w_encode_post[w_index];
                    }
                }
            }
        }
        w_index++;
    }

    free( w_encode_post );

    return( w_decode_post );
}

/*****************************************************************************/
/*1 機能概要: バッファエンコード関数                                         */
/*2 呼出形式: int Isl_Url_Encode( old_buf, new_buf )                         */
/*3 戻り情報:                                                                */
/*3    ISL_SUCCESS : 正常終了                                                */
/*3    ISL_ERROR   : 異常終了                                                */
/*5 制限事項:                                                                */
/*5    new_bufはold_bufの3倍のバッファサイズを確保しておく                   */
/*6 機能説明:                                                                */
/*6    old_buf内のバッファを1文字ずつ検索し、                                */
/*6    [ space " # % { } | \ ^ ~ [ ] ' ; ? : @ = & ] の時に16進に            */
/*6    変換してnew_bufに格納する                                             */
/*6                                                                          */
/*****************************************************************************/
int Isl_Url_Encode( new_buf, old_buf )
char *old_buf;
char *new_buf;
{
    char *w_fname = "IW_EncodeData";
    char *w_ptr;
    char *w_new_ptr;

    /* NULLが入っているか確認 */

    if( new_buf == NULL ) {
       return( -1 );
    }

    /* NULLが入っているか確認 */
    if( old_buf == NULL ) {
       return( -1 );
    }

    /* 値が入っているか確認*/
    if( strlen( old_buf ) == 0 ) {
        return( 0 );
    }

    /* oud_bufの最後まで繰り返し */
    for( w_ptr = old_buf, w_new_ptr = new_buf ; *w_ptr != '\0' ; w_ptr++ ) {
        switch( *w_ptr ) {
            case ' ' :
            case '"' :
            case '#' :
            case '%' :
            case '{' :
            case '}' :
            case '|' :
            case '/' :
            case '^' :
            case '~' :
            case '[' :
            case ']' :
            case '\'' :
            case ':' :
            case '?' :
            case '@' :
            case '=' :
            case '&' :
                /* 対象文字を16進に変換 */
                sprintf( ( char * )w_new_ptr, "%%%02x", *w_ptr );
                w_new_ptr = w_new_ptr + 3;
                break;
            default :
                /* 変換不要なのでなにもしない */
                *w_new_ptr = *w_ptr;
                w_new_ptr++;
                break;
        }
    }

    *w_new_ptr = '\0';
    return( 0 );
}

/*****************************************************************************/
/*1 機能概要: certd通信設定関数                                              */
/*2 呼出形式: char* Isl_Certd_Connect( dfwexit_config, dfw_confg, iw_info )  */
/*3 戻り情報:                                                                */
/*3    NULL     : 通信先ホスト情報等取得できなかった場合                     */
/*3    NULL以外 : 通信結果                                                   */
/*5 制限事項:                                                                */
/*5    なし                                                                  */
/*6 機能説明:                                                                */
/*6    コンフィグデータからCERTD接続情報を取得する。                         */
/*6    ソケットとリクエストメッセージを作成する。                            */
/*6    CERTDへユーザーIDアクセス制御メッセージを送信し通信結果を取得する。   */
/*6                                                                          */
/*****************************************************************************/
char* Isl_Certd_Connect( dfwexit_config, dfw_confg, iw_info )
ISL_NAMEVALUE *dfwexit_config;
ISL_NAMEVALUE *dfw_confg;
char *iw_info;
{
    char *w_value;
	
	char request[4096];
	char response[4096];
	char sessionid[33];
	char errcode[3];
	int sendsize;
	int sock;
	struct sockaddr_in addr;
	struct hostent *hent;
	char *certd_info;
	int nloop;
	char *separator;
	char *hostname;
	char *port_number;
	char *result;
	
	int result_flg;
	result_flg = 0;
	
	memset( request, 0x00, 4096 );
	memset( response, 0x00, 4096 );
	memset( sessionid, 0x00, 33 );
	memset( errcode, 0x00, 3 );

    /* 引数チェック */
    if ( dfwexit_config == NULL || dfw_confg == NULL || iw_info == NULL ) {
        return( NULL );
    }

	/* リクエスト電文作成 */
	sprintf( request,
			"REQ / ICP/2.0\r\nContent-length: 78\r\n\r\nMSG_ID: ReqAccessUID\r\nIW_INFO: %s\r\nACC_URL: http",
			iw_info );

	sendsize = strlen( request );

	/* リクエスト電文をIceWall暗号化ライブラリにて暗号化 */
	/*ChangeEOF( ( request + 37 ), 78 );*/
	IW_EXCRYPTO *crypto_result;
	crypto_result = IW_ExEncrypto( request, sendsize );

	/* 設定ファイルからCertd接続情報を取得 */
    w_value = Isl_NameValue_GetValue( dfw_confg, DFW_CONF_CERT );
    if ( w_value == NULL ) {
    	return( NULL );
    }

	/* Certd接続情報からホスト名とポート番号を取得 */
	certd_info = strtok( w_value, "," );

	/* 最大で、confに設定された接続情報分ループする。但し上限は50回 */
	while ( certd_info != NULL && nloop < 50 ) {

		/* 取得した文字列が空であれば次の文字列を取得 */
		if ( strlen( certd_info ) <= 0 ) {
			nloop++;
			certd_info = strtok( NULL, "," );
			continue;
		}

		/* 文字列中の「:」の前後で値を抽出 */
		separator = NULL;
		hostname = NULL;
		port_number = NULL;
		separator = strchr( certd_info, ':' );

		/* ホスト名取得 */
		strncpy( hostname, certd_info, separator - certd_info );

		/* ポート番号取得 */
		if ( strlen( separator ) <= 1 ) {
			/* ポート番号を取得できなかったらデフォルト(14142)を設定 */
			strcpy( port_number, DEFAULT_CERT_PORT );
		}
		else {
			strcpy( port_number, separator + 1 );
		}

		/* Certd接続情報の設定 */
		memset( &addr, 0x00, sizeof(struct sockaddr_in) );
		addr.sin_family = AF_INET;
		addr.sin_port = htons( atoi( port_number ) );
		hent = ( struct hostent * )gethostbyname( hostname );
		memcpy( &addr.sin_addr, hent->h_addr, hent->h_length );

		/* Certd接続 */
		sock = socket( AF_INET, SOCK_STREAM, 0 );
		if ( sock == -1 ) {
			/* ソケット作成エラー */
			nloop++;
			certd_info = strtok( NULL, "," );
			continue;
		}

		if ( connect( sock, (struct sockaddr*)&addr, sizeof( addr ) ) < 0 ) {
			/* ソケット接続エラー */
			shutdown( sock, SHUT_RDWR );
			close( sock );
			nloop++;
			certd_info = strtok( NULL, "," );
			continue;
		}

		if ( send( sock, crypto_result->buff, crypto_result->bufflen, 0 ) < 0 ) {
			/* リクエスト送信エラー */
			shutdown( sock, SHUT_RDWR );
			close( sock );
			nloop++;
			certd_info = strtok( NULL, "," );
			continue;
		}

		if ( recv( sock, response, 4096, 0 ) < 0 ) {
			/* レスポンス受信エラー */
			shutdown( sock, SHUT_RDWR );
			close( sock );
			nloop++;
			certd_info = strtok( NULL, "," );
			continue;
		}

		shutdown( sock, SHUT_RDWR );
		close( sock );

	    /* レスポンスデータの復号化 */
		if ( strstr( response, "ICP/2.0 200 OK" ) == NULL ) {
			/* エラーのため、次の文字列を取得 */
			nloop++;
			certd_info = strtok( NULL, "," );
		}

		/* 成功ならループを抜ける */
		result_flg = 1;
		break;
	}

	if (result_flg == 1) {
		strcpy( result, response );
		return( result );
	}
	
	return( NULL );
}

void EXCPT_EOF( char *buff, int bufflen );

IW_EXCRYPTO *IW_ExEncrypto( char *buff, int bufflen )
{
	IW_EXCRYPTO *excrypto;
	excrypto = IW_ExCPTCreateCrypto( buff, bufflen, 0, NULL );
	EXCPT_EOF( excrypto->buff, excrypto->bufflen );
	return( excrypto );
}

IW_EXCRYPTO *IW_ExDecrypto( char *buff, int bufflen )
{
	IW_EXCRYPTO *excrypto;
	excrypto = IW_ExCPTCreateCrypto( buff, bufflen, 0, NULL );
	EXCPT_EOF( excrypto->buff, excrypto->bufflen );
	return( excrypto );
}

void EXCPT_EOF( char *buff, int bufflen )
{
	char ascii;
	int count;
	int index;
	index = 0;

	for( count = 0; count < bufflen; count++ ){
		/* ASCII 4bit */
		ascii = CRYPTOKEY[index++] & 0x0F;

		if( index >= 54 ) index = 0;

		/* EOR */
		buff[count] ^= ascii;

		/* 0x7f */
		if( buff[count] == 0x7F ) buff[count] ^= ascii;
	}
}

