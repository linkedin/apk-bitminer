import struct
import sys


class ByteStream(object):
    """
    Class to read from little-endian formatted bytestream
    """

    LITTLE_ENDIAN_INT_FORMAT = "<i"
    LITTLE_ENDIAN_SHORT_FORMAT = "<h"
    LITTLE_ENDIAN_LONG_FORMAT = "<l"
    LITTLE_ENDIAN_FLOAT_FORMAT = "<f"
    LITTLE_ENDIAN_DOUBLE_FORMAT = "<d"
    LITTLE_ENDIAN_LONG_LONG_FORMAT = "<q"

    def __init__(self, path):
        self._path = path
        self._file = open(self._path, 'r+b')
        self._file.seek(0, 2)
        self._size = self._file.tell()
        self._file.seek(0)
        self._look_ahead = None
        self._look_ahead_pos = None
        self._look_ahead_index = None

    @property
    def size(self):
        return self._size

    class ContiguousReader(object):
        """
        Reader over a contiguous stream of bytes.  Entering this context manager
        will capture the current offset which will be restored on exit.
        """

        def __init__(self, bytestream, offset=None):
            self._offset_on_exit = bytestream.tell()
            self._offset = offset
            self._bytestream = bytestream
            self._file = bytestream._file

        def __enter__(self, *args, **kargs):
            if self._offset is not None:
                self._bytestream.seek(self._offset)
            return self

        def __exit__(self, *args, **kargs):
            if self._offset is not None:
                self._bytestream.seek(self._offset_on_exit)

        def read_byte(self):
            """
            :return: single byte read from stream (incrementing position in stream)
            """
            return self._file.read(1)[0] if sys.version_info >= (3,) else ord(self._file.read(1)[0])

        def read_short(self):
            """
            :return: short read from stream, with proper endian-ness in mind
            """
            return struct.unpack(ByteStream.LITTLE_ENDIAN_SHORT_FORMAT, self._file.read(2))[0]

        def read_int(self):
            """
            :return: int read from stream, with proper endian-ness in mind
            """
            return struct.unpack(ByteStream.LITTLE_ENDIAN_INT_FORMAT, self._file.read(4))[0]

        def read_long_long(self):
            """
            :return: long read from stream, with proper endian-ness in mind
            """
            return struct.unpack(ByteStream.LITTLE_ENDIAN_LONG_LONG_FORMAT, self._file.read(8))[0]

        def read_float(self):
            """
            :return: float read from stream, with proper endian-ness in mind
            """
            return struct.unpack(ByteStream.LITTLE_ENDIAN_FLOAT_FORMAT, self._file.read(4))[0]

        def read_double(self):
            """
            :return: double read from stream, with proper endian-ness in mind
            """
            return struct.unpack(ByteStream.LITTLE_ENDIAN_DOUBLE_FORMAT, self._file.read(8))[0]

        def read_ints(self, count):
            """
            :param count: the number of ints to read
            :return: request tuple of int value read from stream, with proper endian-ness in mind
            """
            return struct.unpack("<%di" % count, self._file.read(count * 4))

        def read_leb128(self):
            """
            :return: a Little Endian Base 128 variable-length element from this stream
            """
            result = 0
            shift = 0
            while True:
                current = self.read_byte()
                result |= ((current & 0x7f) << shift)
                if (current & 0x80) == 0:
                    break
                shift += 7
                if shift >= 35:
                    raise Exception("LEB128 sequence invalid")
            return result

        def read_bytes(self, byte_count):
            """
            :param byte_count: number of bytes to read
            :return: requested number of bytes read form stream
            """
            return bytes(self._file.read(byte_count))

        def read_string(self):
            """
            :return: null-treminated string read from stream
            """
            pos = self._file.tell()
            result = ""
            byte_data = self._file.read(128)
            while byte_data:
                fmt = "<%ds" % len(byte_data)
                delta = struct.unpack(fmt, byte_data)[0].decode('latin-1').split(chr(0))[0]
                result += delta
                if len(byte_data) == 128 and len(delta) == 128:
                    byte_data = self._file.read(128)
                else:
                    byte_data = None
            pos += len(result)
            self._file.seek(pos)
            return result

        def read_fixed_string(self, length):
            """
            :param length: size of fixed-length string to read
            :return: string of given lenght, pulled from this stream
            """
            fmt = "<%ds" % length
            return struct.unpack(fmt, self._file.read(length))[0].decode('latin-1')

        def read(self, count):
            """
            :param count: number of bytes to read from stream
            :return: count number of bytes, pulled from this stream
            """
            return self._file.read(count)

        def skip(self, count):
            self._bytestream.seek(self._bytestream.tell() + count)

    def parse_descriptor(self, string_id):
        """
        :param string_id: string id to look up
        :return: string value read from byte stream associated with provided string_id
        """
        with ByteStream.ContiguousReader(self, offset=string_id.data_offset) as reader:
            # read past unused:
            reader.read_leb128()
            return reader.read_string()

    def parse_method_name(self, method_id):
        """
        :param method_id: id for lookup
        :return: string name of method associated with provided method_id
        """
        string_id = method_id._string_ids[method_id.name_index]
        return self.parse_descriptor(string_id)

    class BaseCollectionReader(object):
        """
        This reader holds a starting offset that is used to read into a stream at a given index into
        a collection of like objects.  This way, each item requested is processed into memory only on
        an on-demand basis.
        """

        def __init__(self, bytestream, clazz, offset=None, count=None):
            """
            :param bytestream: stream to read from
            :param offset: where in stream to read from
            :param obj_size: size of each object to be pulled
            :param clazz: `DexParser.Item` subclass to parse into
            """
            self._bytestream = bytestream
            self._count = count
            if clazz.FORMAT is None or clazz.FORMAT[0] == '*':
                self._byte_size = None
                self._fmt = None
            else:
                self._fmt = "<" + clazz.FORMAT
                self._byte_size = struct.calcsize(self._fmt)
            self._offset = offset
            self._index = 0
            self._class = clazz
            self._curr_offset = offset if offset is not None else bytestream.tell()

    class IterReader(BaseCollectionReader):
        """
        This class is used for reading elements one by one out of the binary stream,
        intended for use only in a continuous read over a collection
        If an explicit offset is given, each iteration will return to the starting offset within the stream,
        but continue where the reader left off for next iteration;  this can be expensive
        """

        def __iter__(self):
            return self

        def next(self):
            if self._count is not None and self._index >= self._count:
                raise StopIteration()
            start_offset = self._bytestream.tell()
            try:
                self._bytestream.seek(self._curr_offset)
                if self._byte_size is not None:
                    elem = self._class(self._bytestream,  struct.unpack(self._fmt,
                                                                        self._bytestream._file.read(self._byte_size )))
                else:
                    elem = self._class(self._bytestream)
                self._curr_offset = self._bytestream.tell()
                self._index += 1
                return elem
            finally:
                if self._offset is not None:
                    self._bytestream.seek(start_offset)

    class CollectionReader(BaseCollectionReader):

        def __init__(self, bytestream, clazz, offset=None, count=None):
            super(ByteStream.CollectionReader, self).__init__(bytestream, clazz, offset, count)
            self._offset = offset if offset is not None else bytestream.tell()
            self._parsed = {}

        def __getitem__(self, index):
            if self._count is not None and index >= self._count:
                raise IndexError("Index out of range")
            if index in self._parsed:
                return self._parsed[index]
            start_offset = self._bytestream.tell()
            self._bytestream.seek(self._offset + index * self._byte_size)
            try:
                if self._byte_size is not None:
                    elem = self._class(self._bytestream,  struct.unpack(self._fmt,
                                                                        self._bytestream._file.read(self._byte_size )))
                else:
                    elem = self._class(self._bytestream)
                self._parsed[index] = elem
                return elem
            finally:
                self._bytestream.seek(start_offset)

        def parse_items(self, count, start=0):
            """
            Retrieve list of same-type items from stream.  Offset into stream is unchanged upon exit
            :param count: number of iteams of type clazz to parse
            :return: collection of requested number of clazz instances parsed from bytestream
            """
            if count != 0:
                current_offset = self._file.tell()
                self._bytestream.seek(self._offset + start*size)
                try:
                    return clazz.get(self, count)
                finally:
                    if offset is not None:
                        self._file.seek(current_offset)

    def tell(self):
        """
        :return: current location within this stream
        """
        return self._file.tell()

    def seek(self, pos):
        """
        :param pos: position to seek to within the stream
        :return: position after seek
        """
        return self._file.seek(pos)


