/*---------------------------------------------------------------------------*/
/*  定数定義                                                                 */
/*---------------------------------------------------------------------------*/
#define ISL3_LOG_NONE          0            /* ログ出力なし                  */
#define ISL3_LOG_FATAL         1            /* FATALレベル                   */
#define ISL3_LOG_WARNING       2            /* WARNINGレベル                 */
#define ISL3_LOG_INFO          3            /* INFOレベル                    */

/* エラーコード */
#define ISL_SUCCESS            0            /* 正常終了                      */
#define ISL_ERROR             -1            /* 異常終了                      */
#define ISL_ERR_NOMEM          1            /* メモリ不足エラー              */
#define ISL_ERR_TIMEOUT       10            /* タイムアウトエラー            */ 
#define ISL_ERR_FOPEN         20            /* ファイルOpenエラー            */

/* ログレベル */
#define ISL_LOG_NONE           0            /* ログ出力なし                  */
#define ISL_LOG_FATAL          1            /* FATALレベル                   */
#define ISL_LOG_WARNING        2            /* WARNINGレベル                 */
#define ISL_LOG_INFO           3            /* INFOレベル                    */

/* Isl_Certd_Connect使用定数 */
#define DFW_CONF_CERT          "CERT"       /* dfw.conf内のCertd接続情報設定項目 */
#define DEFAULT_CERT_PORT      "14142"      /* Certdデフォルト接続ポート     */

/*---------------------------------------------------------------------------*/
/*  構造体定義                                                               */
/*---------------------------------------------------------------------------*/
typedef struct {
    char       *buffer;        /* データバッファ格納ポインタ                 */
    int         buf_len;       /* データバッファ内のデータ長                 */
    int         buf_size;      /* データバッファの現在のサイズ(malloc値)     */
    int         alloc_size;    /* データバッファのアロケートサイズ(malloc値) */
    int         errcode;       /* エラーコード格納領域                       */
} ISL_BUFFER;

typedef struct ISL_NAMEVAL_ELEMENT  ISL_NAMEVAL_ELEMENT;
struct ISL_NAMEVAL_ELEMENT {
    char                *name;
    char                *value;
    ISL_NAMEVAL_ELEMENT *next;
    ISL_NAMEVAL_ELEMENT *prev;
};

typedef struct ISL_NAMEVALUE        ISL_NAMEVALUE;
struct ISL_NAMEVALUE {
    int                 count;
    ISL_NAMEVAL_ELEMENT *first;
    ISL_NAMEVAL_ELEMENT *last;
};

/*---------------------------------------------------------------------------*/
/* プロトタイプ宣言                                                          */
/*---------------------------------------------------------------------------*/
void Isl_LogInit( char *e_file, int e_level, char *a_file, int a_level, char *t_file, int t_level );
void Isl_LogTrace( int level, char *logmsg, ... );
void Isl_LogAccess( int level, char *logmsg, ... );
void Isl_LogError( int level, char *logmsg, ... );

ISL_BUFFER *Isl_Buf_Create( int alloc_size );
int   Isl_Buf_Release( ISL_BUFFER *st_buf );
int   Isl_Buf_AddBuf( ISL_BUFFER *st_buf, char *buffer, int buf_len );
int   Isl_Buf_SetBuf( ISL_BUFFER *st_buf, char *buffer, int buf_len );
char *Isl_Buf_GetBuf( ISL_BUFFER *st_buf );
int   Isl_Alloc( char **buffer, int buf_size, int alloc_size, int ch_ini );
int   Isl_Free( char **buffer );

int Isl_ConfigRead( ISL_NAMEVALUE *nameval, char *filename );

ISL_NAMEVALUE *Isl_NameValue_Create();
int   Isl_NameValue_Release(ISL_NAMEVALUE *nameval);
int   Isl_NameValue_Add(ISL_NAMEVALUE *nameval, char *name, char *value);
char  *Isl_NameValue_GetValue(ISL_NAMEVALUE *nameval, char *name);
char  *Isl_NameValue_ALLGetVal(ISL_NAMEVALUE *nameval, char *name, int *number);

char  *Isl_Url_Decode( char *postdata );
int   Isl_Url_Encode(char *new_buf, char *old_buf );
