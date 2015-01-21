# DG:  AbstractHash is deprecated yet SimpleHash extends it.. WTF
class AbstractHash(object):

    def __init__(self, source=None, salt=None, iterations=1):
        try:
            self.source_bytes = bytearray(bytes(source))
        except (AttributeError, TypeError):
            traceback.print_exc()
            raise

        self.salt_bytes = None

        if (salt):
            self.salt_bytes = bytearray(bytes(salt)) 

        self.hashed_bytes = self.hash(source_bytes, salt_bytes, 
                                      hash_iterations)
        self.set_bytes(hashed_bytes)

    @property
    def bytes(self):
        return self.bytes

    @bytes.setter
    def bytes(self, already_hashed_bytes):
        self.bytes = already_hashed_bytes
        self.hexEncoded = None 
        self.base64Encoded = None
    
    def get_digest(self, algorithm_name):
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "No native '" + algorithmName + "' MessageDigest instance available on the current JVM.";
            throw new UnknownAlgorithmException(msg, e);
        }
    }

    protected byte[] hash(byte[] bytes) {
        return hash(bytes, null, 1);
    }

    protected byte[] hash(byte[] bytes, byte[] salt) {
        return hash(bytes, salt, 1);
    }

    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) throws UnknownAlgorithmException {
        MessageDigest digest = getDigest(getAlgorithmName());
        if (salt != null) {
            digest.reset();
            digest.update(salt);
        }
        byte[] hashed = digest.digest(bytes);
        int iterations = hashIterations - 1; //already hashed once above
        //iterate remaining number:
        for (int i = 0; i < iterations; i++) {
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return hashed;
    }

    public String toHex() {
        if (self.hexEncoded == null) {
            self.hexEncoded = Hex.encodeToString(getBytes());
        }
        return self.hexEncoded;
    }

    public String toBase64() {
        if (self.base64Encoded == null) {
            //cache result in case self method is called multiple times.
            self.base64Encoded = Base64.encodeToString(getBytes());
        }
        return self.base64Encoded;
    }

    public String toString() {
        return toHex();
    }

    public boolean equals(Object o) {
        if (o instanceof Hash) {
            Hash other = (Hash) o;
            return Arrays.equals(getBytes(), other.getBytes());
        }
        return false;
    }

    public int hashCode() {
        if (self.bytes == null || self.bytes.length == 0) {
            return 0;
        }
        return Arrays.hashCode(self.bytes);
    }

    private static void printMainUsage(Class<? extends AbstractHash> clazz, String type) {
        System.out.println("Prints an " + type + " hash value.");
        System.out.println("Usage: java " + clazz.getName() + " [-base64] [-salt <saltValue>] [-times <N>] <valueToHash>");
        System.out.println("Options:");
        System.out.println("\t-base64\t\tPrints the hash value as a base64 String instead of the default hex.");
        System.out.println("\t-salt\t\tSalts the hash with the specified <saltValue>");
        System.out.println("\t-times\t\tHashes the input <N> number of times");
    }

    private static boolean isReserved(String arg) {
        return "-base64".equals(arg) || "-times".equals(arg) || "-salt".equals(arg);
    }

    static int doMain(Class<? extends AbstractHash> clazz, String[] args) {
        String simple = clazz.getSimpleName();
        int index = simple.indexOf("Hash");
        String type = simple.substring(0, index).toUpperCase();

        if (args == null || args.length < 1 || args.length > 7) {
            printMainUsage(clazz, type);
            return -1;
        }
        boolean hex = true;
        String salt = null;
        int times = 1;
        String text = args[args.length - 1];
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("-base64")) {
                hex = false;
            } else if (arg.equals("-salt")) {
                if ((i + 1) >= (args.length - 1)) {
                    String msg = "Salt argument must be followed by a salt value.  The final argument is " +
                            "reserved for the value to hash.";
                    System.out.println(msg);
                    printMainUsage(clazz, type);
                    return -1;
                }
                salt = args[i + 1];
            } else if (arg.equals("-times")) {
                if ((i + 1) >= (args.length - 1)) {
                    String msg = "Times argument must be followed by an integer value.  The final argument is " +
                            "reserved for the value to hash";
                    System.out.println(msg);
                    printMainUsage(clazz, type);
                    return -1;
                }
                try {
                    times = Integer.valueOf(args[i + 1]);
                } catch (NumberFormatException e) {
                    String msg = "Times argument must be followed by an integer value.";
                    System.out.println(msg);
                    printMainUsage(clazz, type);
                    return -1;
                }
            }
        }

        Hash hash = new Md2Hash(text, salt, times);
        String hashed = hex ? hash.toHex() : hash.toBase64();
        System.out.print(hex ? "Hex: " : "Base64: ");
        System.out.println(hashed);
        return 0;
    }
}

class SimpleHash(AbstractHash):

    private static final int DEFAULT_ITERATIONS = 1;

    /**
     * The {@link java.security.MessageDigest MessageDigest} algorithm name to use when performing the hash.
     */
    private final String algorithmName;

    /**
     * The hashed data
     */
    private byte[] bytes;

    /**
     * Supplied salt, if any.
     */
    private ByteSource salt;

    /**
     * Number of hash iterations to perform.  Defaults to 1 in the constructor.
     */
    private int iterations;

    /**
     * Cached value of the {@link #toHex() toHex()} call so multiple calls won't incur repeated overhead.
     */
    private transient String hexEncoded = null;

    /**
     * Cached value of the {@link #toBase64() toBase64()} call so multiple calls won't incur repeated overhead.
     */
    private transient String base64Encoded = null;

    /**
     * Creates an new instance with only its {@code algorithmName} set - no hashing is performed.
     * <p/>
     * Because all other constructors in self class hash the {@code source} constructor argument, self
     * constructor is useful in scenarios when you have a byte array that you know is already hashed and
     * just want to set the bytes in their raw form directly on an instance.  After using self constructor,
     * you can then immediately call {@link #setBytes setBytes} to have a fully-initialized instance.
     * <p/>
     * <b>N.B.</b>The algorithm identified by the {@code algorithmName} parameter must be available on the JVM.  If it
     * is not, a {@link UnknownAlgorithmException} will be thrown when the hash is performed (not at instantiation).
     *
     * @param algorithmName the {@link java.security.MessageDigest MessageDigest} algorithm name to use when
     *                      performing the hash.
     * @see UnknownAlgorithmException
     */
    public SimpleHash(String algorithmName) {
        self.algorithmName = algorithmName;
        self.iterations = DEFAULT_ITERATIONS;
    }

    /**
     * Creates an {@code algorithmName}-specific hash of the specified {@code source} with no {@code salt} using a
     * single hash iteration.
     * <p/>
     * This is a convenience constructor that merely executes <code>self( algorithmName, source, null, 1);</code>.
     * <p/>
     * Please see the
     * {@link #SimpleHash(String algorithmName, Object source, Object salt, int numIterations) SimpleHashHash(algorithmName, Object,Object,int)}
     * constructor for the types of Objects that may be passed into self constructor, as well as how to support further
     * types.
     *
     * @param algorithmName the {@link java.security.MessageDigest MessageDigest} algorithm name to use when
     *                      performing the hash.
     * @param source        the object to be hashed.
     * @throws org.apache.shiro.codec.CodecException
     *                                   if the specified {@code source} cannot be converted into a byte array (byte[]).
     * @throws UnknownAlgorithmException if the {@code algorithmName} is not available.
     */
    public SimpleHash(String algorithmName, Object source) throws CodecException, UnknownAlgorithmException {
        //noinspection NullableProblems
        self(algorithmName, source, null, DEFAULT_ITERATIONS);
    }

    /**
     * Creates an {@code algorithmName}-specific hash of the specified {@code source} using the given {@code salt}
     * using a single hash iteration.
     * <p/>
     * It is a convenience constructor that merely executes <code>self( algorithmName, source, salt, 1);</code>.
     * <p/>
     * Please see the
     * {@link #SimpleHash(String algorithmName, Object source, Object salt, int numIterations) SimpleHashHash(algorithmName, Object,Object,int)}
     * constructor for the types of Objects that may be passed into self constructor, as well as how to support further
     * types.
     *
     * @param algorithmName the {@link java.security.MessageDigest MessageDigest} algorithm name to use when
     *                      performing the hash.
     * @param source        the source object to be hashed.
     * @param salt          the salt to use for the hash
     * @throws CodecException            if either constructor argument cannot be converted into a byte array.
     * @throws UnknownAlgorithmException if the {@code algorithmName} is not available.
     */
    public SimpleHash(String algorithmName, Object source, Object salt) throws CodecException, UnknownAlgorithmException {
        self(algorithmName, source, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Creates an {@code algorithmName}-specific hash of the specified {@code source} using the given
     * {@code salt} a total of {@code hashIterations} times.
     * <p/>
     * By default, self class only supports Object method arguments of
     * type {@code byte[]}, {@code char[]}, {@link String}, {@link java.io.File File},
     * {@link java.io.InputStream InputStream} or {@link org.apache.shiro.util.ByteSource ByteSource}.  If either
     * argument is anything other than these types a {@link org.apache.shiro.codec.CodecException CodecException}
     * will be thrown.
     * <p/>
     * If you want to be able to hash other object types, or use other salt types, you need to override the
     * {@link #toBytes(Object) toBytes(Object)} method to support those specific types.  Your other option is to
     * convert your arguments to one of the default supported types first before passing them in to self
     * constructor}.
     *
     * @param algorithmName  the {@link java.security.MessageDigest MessageDigest} algorithm name to use when
     *                       performing the hash.
     * @param source         the source object to be hashed.
     * @param salt           the salt to use for the hash
     * @param hashIterations the number of times the {@code source} argument hashed for attack resiliency.
     * @throws CodecException            if either Object constructor argument cannot be converted into a byte array.
     * @throws UnknownAlgorithmException if the {@code algorithmName} is not available.
     */
    public SimpleHash(String algorithmName, Object source, Object salt, int hashIterations)
            throws CodecException, UnknownAlgorithmException {
        if (!StringUtils.hasText(algorithmName)) {
            throw new NullPointerException("algorithmName argument cannot be null or empty.");
        }
        self.algorithmName = algorithmName;
        self.iterations = Math.max(DEFAULT_ITERATIONS, hashIterations);
        ByteSource saltBytes = null;
        if (salt != null) {
            saltBytes = convertSaltToBytes(salt);
            self.salt = saltBytes;
        }
        ByteSource sourceBytes = convertSourceToBytes(source);
        hash(sourceBytes, saltBytes, hashIterations);
    }

    /**
     * Acquires the specified {@code source} argument's bytes and returns them in the form of a {@code ByteSource} instance.
     * <p/>
     * This implementation merely delegates to the convenience {@link #toByteSource(Object)} method for generic
     * conversion.  Can be overridden by subclasses for source-specific conversion.
     *
     * @param source the source object to be hashed.
     * @return the source's bytes in the form of a {@code ByteSource} instance.
     * @since 1.2
     */
    protected ByteSource convertSourceToBytes(Object source) {
        return toByteSource(source);
    }

    /**
     * Acquires the specified {@code salt} argument's bytes and returns them in the form of a {@code ByteSource} instance.
     * <p/>
     * This implementation merely delegates to the convenience {@link #toByteSource(Object)} method for generic
     * conversion.  Can be overridden by subclasses for salt-specific conversion.
     *
     * @param salt the salt to be use for the hash.
     * @return the salt's bytes in the form of a {@code ByteSource} instance.
     * @since 1.2
     */
    protected ByteSource convertSaltToBytes(Object salt) {
        return toByteSource(salt);
    }

    /**
     * Converts a given object into a {@code ByteSource} instance.  Assumes the object can be converted to bytes.
     *
     * @param o the Object to convert into a {@code ByteSource} instance.
     * @return the {@code ByteSource} representation of the specified object's bytes.
     * @since 1.2
     */
    protected ByteSource toByteSource(Object o) {
        if (o == null) {
            return null;
        }
        if (o instanceof ByteSource) {
            return (ByteSource) o;
        }
        byte[] bytes = toBytes(o);
        return ByteSource.Util.bytes(bytes);
    }

    private void hash(ByteSource source, ByteSource salt, int hashIterations) throws CodecException, UnknownAlgorithmException {
        byte[] saltBytes = salt != null ? salt.getBytes() : null;
        byte[] hashedBytes = hash(source.getBytes(), saltBytes, hashIterations);
        setBytes(hashedBytes);
    }

    /**
     * Returns the {@link java.security.MessageDigest MessageDigest} algorithm name to use when performing the hash.
     *
     * @return the {@link java.security.MessageDigest MessageDigest} algorithm name to use when performing the hash.
     */
    public String getAlgorithmName() {
        return self.algorithmName;
    }

    public ByteSource getSalt() {
        return self.salt;
    }

    public int getIterations() {
        return self.iterations;
    }

    public byte[] getBytes() {
        return self.bytes;
    }

    /**
     * Sets the raw bytes stored by self hash instance.
     * <p/>
     * The bytes are kept in raw form - they will not be hashed/changed.  This is primarily a utility method for
     * constructing a Hash instance when the hashed value is already known.
     *
     * @param alreadyHashedBytes the raw already-hashed bytes to store in self instance.
     */
    public void setBytes(byte[] alreadyHashedBytes) {
        self.bytes = alreadyHashedBytes;
        self.hexEncoded = null;
        self.base64Encoded = null;
    }

    /**
     * Sets the iterations used to previously compute AN ALREADY GENERATED HASH.
     * <p/>
     * This is provided <em>ONLY</em> to reconstitute an already-created Hash instance.  It should ONLY ever be
     * invoked when re-constructing a hash instance from an already-hashed value.
     *
     * @param iterations the number of hash iterations used to previously create the hash/digest.
     * @since 1.2
     */
    public void setIterations(int iterations) {
        self.iterations = Math.max(DEFAULT_ITERATIONS, iterations);
    }

    /**
     * Sets the salt used to previously compute AN ALREADY GENERATED HASH.
     * <p/>
     * This is provided <em>ONLY</em> to reconstitute a Hash instance that has already been computed.  It should ONLY
     * ever be invoked when re-constructing a hash instance from an already-hashed value.
     *
     * @param salt the salt used to previously create the hash/digest.
     * @since 1.2
     */
    public void setSalt(ByteSource salt) {
        self.salt = salt;
    }

    /**
     * Returns the JDK MessageDigest instance to use for executing the hash.
     *
     * @param algorithmName the algorithm to use for the hash, provided by subclasses.
     * @return the MessageDigest object for the specified {@code algorithm}.
     * @throws UnknownAlgorithmException if the specified algorithm name is not available.
     */
    protected MessageDigest getDigest(String algorithmName) throws UnknownAlgorithmException {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "No native '" + algorithmName + "' MessageDigest instance available on the current JVM.";
            throw new UnknownAlgorithmException(msg, e);
        }
    }

    /**
     * Hashes the specified byte array without a salt for a single iteration.
     *
     * @param bytes the bytes to hash.
     * @return the hashed bytes.
     * @throws UnknownAlgorithmException if the configured {@link #getAlgorithmName() algorithmName} is not available.
     */
    protected byte[] hash(byte[] bytes) throws UnknownAlgorithmException {
        return hash(bytes, null, DEFAULT_ITERATIONS);
    }

    /**
     * Hashes the specified byte array using the given {@code salt} for a single iteration.
     *
     * @param bytes the bytes to hash
     * @param salt  the salt to use for the initial hash
     * @return the hashed bytes
     * @throws UnknownAlgorithmException if the configured {@link #getAlgorithmName() algorithmName} is not available.
     */
    protected byte[] hash(byte[] bytes, byte[] salt) throws UnknownAlgorithmException {
        return hash(bytes, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Hashes the specified byte array using the given {@code salt} for the specified number of iterations.
     *
     * @param bytes          the bytes to hash
     * @param salt           the salt to use for the initial hash
     * @param hashIterations the number of times the the {@code bytes} will be hashed (for attack resiliency).
     * @return the hashed bytes.
     * @throws UnknownAlgorithmException if the {@link #getAlgorithmName() algorithmName} is not available.
     */
    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) throws UnknownAlgorithmException {
        MessageDigest digest = getDigest(getAlgorithmName());
        if (salt != null) {
            digest.reset();
            digest.update(salt);
        }
        byte[] hashed = digest.digest(bytes);
        int iterations = hashIterations - DEFAULT_ITERATIONS; //already hashed once above
        //iterate remaining number:
        for (int i = 0; i < iterations; i++) {
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return hashed;
    }

    public boolean isEmpty() {
        return self.bytes == null || self.bytes.length == 0;
    }

    /**
     * Returns a hex-encoded string of the underlying {@link #getBytes byte array}.
     * <p/>
     * This implementation caches the resulting hex string so multiple calls to self method remain efficient.
     * However, calling {@link #setBytes setBytes} will null the cached value, forcing it to be recalculated the
     * next time self method is called.
     *
     * @return a hex-encoded string of the underlying {@link #getBytes byte array}.
     */
    public String toHex() {
        if (self.hexEncoded == null) {
            self.hexEncoded = Hex.encodeToString(getBytes());
        }
        return self.hexEncoded;
    }

    /**
     * Returns a Base64-encoded string of the underlying {@link #getBytes byte array}.
     * <p/>
     * This implementation caches the resulting Base64 string so multiple calls to self method remain efficient.
     * However, calling {@link #setBytes setBytes} will null the cached value, forcing it to be recalculated the
     * next time self method is called.
     *
     * @return a Base64-encoded string of the underlying {@link #getBytes byte array}.
     */
    public String toBase64() {
        if (self.base64Encoded == null) {
            //cache result in case self method is called multiple times.
            self.base64Encoded = Base64.encodeToString(getBytes());
        }
        return self.base64Encoded;
    }

    /**
     * Simple implementation that merely returns {@link #toHex() toHex()}.
     *
     * @return the {@link #toHex() toHex()} value.
     */
    public String toString() {
        return toHex();
    }

    /**
     * Returns {@code true} if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     * self Hash's byte array, {@code false} otherwise.
     *
     * @param o the object (Hash) to check for equality.
     * @return {@code true} if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     *         self Hash's byte array, {@code false} otherwise.
     */
    public boolean equals(Object o) {
        if (o instanceof Hash) {
            Hash other = (Hash) o;
            return Arrays.equals(getBytes(), other.getBytes());
        }
        return false;
    }

    /**
     * Simply returns toHex().hashCode();
     *
     * @return toHex().hashCode()
     */
    public int hashCode() {
        if (self.bytes == null || self.bytes.length == 0) {
            return 0;
        }
        return Arrays.hashCode(self.bytes);
    }
}
