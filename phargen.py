

import phpserialize as psr
import struct 
import zlib
import hashlib

# This is not the best code. But it works :)
#
#


PHAR_STUB_BEGIN  = b"<?PHP"
PHAR_HALT_TOKEN  = b"__HALT_COMPILER();" + b" " + b"?>\r\n"
#                  mandatory ---^         ^------^------- optional
# from php.net : 
# There are no restrictions on the contents of a Phar stub, 
# except for the requirement that it conclude with __HALT_COMPILER();. The closing PHP tag ?>
# may be included or omitted, but there can be no more than 1 space between the ; and the close tag
 
PHAR_BITMAP_VER_SIG = 0x00010000	  
PHAR_BITMAP_DEFLATE = 0x00001000  # not implemented
PHAR_BITMAP_BZIP2   = 0x00002000  # not implemented
PHAR_BITMAP_WTF1    = 0x00000100  # not implemented
#0x00010000	If set, this Phar contains a verification signature
#0x00001000	If set, this Phar contains at least 1 file that is compressed with zlib DEFLATE compression
#0x00002000	If set, this Phar contains at least 1 file that is compressed with bzip2 compression

PHAR_FILE_BITMAP_DEFAULT = 0
PHAR_FILE_BITMAP_DEFLATE = 0x00001000 # not implemented
PHAR_FILE_BITMAP_BZIP2   = 0x00002000 # not implemented

#0x000001FF	These bits are reserved for defining specific file permissions of a file. 
#           Permissions are used for fstat() and can be used to recreate desired permissions upon extraction.
#0x00001000	If set, this file is compressed with zlib DEFLATE compression
#0x00002000	If set, this file is compressed with bzip2 compression



PHAR_SIG_MD5  =  0x0001 
PHAR_SIG_SHA1 =  0x0002  # not implemented
PHAR_SIG_MAGIC = b'GBMB'

#varying	The actual signature, 20 bytes for an SHA1 signature, 
#  16 bytes for an MD5 signature, 32 bytes for an SHA256 signature, 
#  and 64 bytes for an SHA512 signature. 
# The length of an OPENSSL signature depends on the size of the private key.
#4 bytes	Signature flags. 0x0001 is used to define an MD5 signature, 0x0002 is used to define an SHA1 signature,
#  0x0003 is used to define an SHA256 signature, and 0x0004 is used to define an SHA512 signature. 
# The SHA256 and SHA512 signature support is available as of API version 1.1.0. 
#  0x0010 is used to define an OPENSSL signature, what is available as of API version 1.1.1, 
#  if OpenSSL is available.
#4 bytes	Magic GBMB used to define the presence of a signature



def mk4b(val):
  return struct.pack('I', val)

def mk2b(val):
  return struct.pack("H", val)

def mk1b(val):
  return struct.pack('B', val)

def mk_size_value(val):
  return mk4b(len(val)) + val

def mk_crc32(val):
  return mk4b( zlib.crc32(val) & 0x00FFffFFff )



class PharFile:
  filename = b'file1'
  timestamp = 0x12
  bitmap = PHAR_FILE_BITMAP_DEFAULT
  meta = None
  content  = b'data'

  def __init__(self, name, data=b''):
    self.filename = name
    self.content = data

  def serialize_meta(self):
    if self.meta:
      return psr.dumps(self.meta)
    return b''

  def compile(self):
    # compression unsupported :P
    content_size = len(self.content)
    # content_size = 0xFFffFFfe

    blob = b''
    blob += mk_size_value(self.filename)
    blob += mk4b( content_size ) # uncompress size
    blob += mk4b( self.timestamp )
    blob += mk4b( content_size ) # compress size
    blob += mk_crc32( self.content )
    blob += mk4b( self.bitmap )
    blob += mk_size_value(  self.serialize_meta() )

    return blob


class PharGenerator:

  prefix = b''
  stub   = b''
  meta = None
  api_version = 0x11
  bitmap = PHAR_BITMAP_VER_SIG
  alias = b''
  files = None

  hash_flag = PHAR_SIG_MD5

  def __init__(self):
    pass 
    self.files = []

  def serialize_meta(self):
    if self.meta:
      return psr.dumps(self.meta)
    return b''

  def compile_meta(self):
    return mk_size_value( self.serialize_meta() )

  def compile_files_meta(self):
    blob = b''
    for f in self.files:
      # print("File meta ++ ")
      blob += f.compile()
    return blob

  def compile_files_data(self):
    blob = b''
    for f in self.files:
      # print("File data ++ ")
      blob += f.content
    return blob

  def compile_manifest(self):
    blob = b''
    blob += mk4b( len(self.files) )
    blob += mk2b( self.api_version ) 
    blob += mk4b( self.bitmap )
    blob += mk_size_value(self.alias)
    blob += self.compile_meta() 
    blob += self.compile_files_meta()
    # return 4b-SIZE + blob     
    return mk_size_value(blob)


  def compile_stub(self):
    blob = b''
    blob += self.prefix
    blob += PHAR_STUB_BEGIN + self.stub + PHAR_HALT_TOKEN
    return blob

  def compile_signature(self, blob):
    hash = b''
    if self.hash_flag & PHAR_SIG_MD5:
      hash = hashlib.md5(blob).digest()
    else:
      raise Exception("Not supported lol")
    return hash + mk4b(self.hash_flag) + PHAR_SIG_MAGIC


  def compile(self):
    blob = b''
    blob += self.compile_stub()
    blob += self.compile_manifest()
    blob += self.compile_files_data()

    if not ( self.bitmap & PHAR_BITMAP_VER_SIG ) :
      return blob
    #else :  
    return blob + self.compile_signature(blob)





if __name__ == '__main__':

  x = PharGenerator()
  x.files.append( PharFile(b'TheFile1', b'aaaa') )
  x.files.append( PharFile(b'TheFile2', b'bbbbcccc') )
  
  x.meta = [
    1,
    "test",
    dict(a=1),
    psr.phpobject(
      'ClassNameHere',
      dict(
        propertyName = 'value'
        )
    )
  ]

  open("tmp.phar","wb").write(x.compile())

# try : phar://tmp.phar/TheFile1
