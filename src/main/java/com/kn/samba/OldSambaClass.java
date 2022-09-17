package com.kn.samba;

public class OldSambaClass {
    private static final String FILE_NOT_FOUND = "File not found...";
    private static final String CONST_SPLIT = "[;|:|@|$]";
    private static final String CONST_SPLIT_SECOND = "[;|:|@]";
    private static final String LABEL_NOT_FOUND = " not found...";
    private static final String LABEL_FILE = "File ";
    private static final String LABEL_FAILDED_TO_READ = "Failed to read: ";

    public SmbRemoteAccessV3() {
        /**
         * Constructor
         *
         */
    }

    @Override
    public String read(String resource) {
        try (SMBClient client = new SMBClient()) {

            SambaConfig sambaConfig = getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig, client);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig
                    .getShare());

            if (!share.fileExists(sambaConfig.getFilePath()))
                throw new FileNotFoundException(FILE_NOT_FOUND);

            File file = getFileToRead(share, sambaConfig);

            BufferedReader b = new BufferedReader(new InputStreamReader(
                    file.getInputStream()));

            String chain = "";
            StringBuilder result = new StringBuilder();
            while ((chain = b.readLine()) != null) {
                result.append(chain).append(LINE_SEPARATOR);
            }

            file.close();
            b.close();
            share.close();

            return result.toString();
        } catch (Exception e) {
            log.error(LABEL_FAILDED_TO_READ.concat(e.getMessage()));
            return null;
        }
    }

    @Override
    public byte[] readBinary(String resource) {
        ByteArrayOutputStream bao = null;
        try (SMBClient client = new SMBClient()) {

            SambaConfig sambaConfig = getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig, client);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig
                    .getShare());

            if (!share.fileExists(sambaConfig.getFilePath())) {
                throw new FileNotFoundException(FILE_NOT_FOUND);
            }

            File file = getFileToRead(share, sambaConfig);

            byte[] buffer = new byte[2 * BUFFER_SIZE];
            int bytesRead = 0;
            BufferedInputStream bi = new BufferedInputStream(
                    file.getInputStream());
            bao = new ByteArrayOutputStream(2 * BUFFER_SIZE);

            while ((bytesRead = bi.read(buffer)) != -1) {
                bao.write(buffer, 0, bytesRead);
            }

            bao.close();
            bi.close();
            file.close();

            return bao.toByteArray();
        } catch (Exception e) {
            log.error(LABEL_FAILDED_TO_READ.concat(e.getMessage()));
            throw new NullPointerException(LABEL_FAILDED_TO_READ.concat(e
                    .getMessage()));
        }
    }

    @Override
    public boolean write(String resource, String lines, String encoding) {

        try (SMBClient client = new SMBClient()) {

            SambaConfig sambaConfig = getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig, client);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig
                    .getShare());

            if (!share.folderExists(sambaConfig.getPath()))
                share.mkdir(sambaConfig.getPath());
            StringBuilder result = new StringBuilder();

            result.append(lines).append(LINE_SEPARATOR);

            try (File file = share.openFile(sambaConfig.getFilePath(),
                    EnumSet.of(AccessMask.FILE_WRITE_DATA),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_SUPERSEDE,
                    EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE))) {

                OutputStream out = file.getOutputStream();
                BufferedWriter writer = new BufferedWriter(
                        new OutputStreamWriter(out, Charset.forName(encoding)));

                writer.write(result.toString());
                writer.flush();
                out.close();

                boolean fileExists = share
                        .fileExists(sambaConfig.getFilePath());
                share.close();

                return fileExists;

            }

        } catch (Exception e) {
            log.error("Failed to write: ".concat(e.getMessage()));
            return false;
        }
    }

    @Override
    public boolean write(String resource, byte[] lines) {

        try (SMBClient client = new SMBClient()) {

            SambaConfig sambaConfig = getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig, client);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig
                    .getShare());

            if (!share.folderExists(sambaConfig.getPath()))
                share.mkdir(sambaConfig.getPath());

            try (File file = share.openFile(sambaConfig.getFilePath(),
                    EnumSet.of(AccessMask.FILE_APPEND_DATA),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_SUPERSEDE,
                    EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE))) {

                OutputStream os = file.getOutputStream();
                os.write(lines);
                os.flush();
                os.close();

            }

            boolean fileExists = share.fileExists(sambaConfig.getFilePath());
            share.close();

            return fileExists;
        } catch (Exception e) {
            log.error("Failed to write: ".concat(e.getMessage()));
            return false;
        }
    }

    @Override
    public String[] list(String resource, String filter) {
        String[] data = null;
        try (SMBClient client = new SMBClient()) {

            SambaConfig sambaConfig = getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig, client);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig
                    .getShare());
            String filterFormat = "*." + filter;

            if (!share.folderExists(sambaConfig.getPath())) {
                throw new FileNotFoundException(LABEL_FILE
                        + sambaConfig.getPath() + LABEL_NOT_FOUND);
            }

            data = share.list(sambaConfig.getPath(), filterFormat).stream()
                    .map(item -> item.getFileName()).toArray(String[]::new);
            share.close();

            return data;
        } catch (Exception e) {
            log.error("Failed to list: ".concat(e.getMessage()));
            return data;
        }
    }

    @Override
    public boolean move(String resource, String sourcePath,
                        String destinationPath) {

        try (SMBClient client = new SMBClient()) {

            SambaConfig sourceConfig = getParametersFromURL(resource);
            Session sourceSession = getAuthentication(sourceConfig, client);

            DiskShare origin = (DiskShare) sourceSession
                    .connectShare(sourceConfig.getShare());

            StringBuilder sbSource = new StringBuilder();
            sbSource.append(sourceConfig.getPath());
            if (sourcePath.lastIndexOf("/") != sourcePath.length() - 1)
                sbSource.append("/");
            sbSource.append(sourcePath);

            sourceConfig.setFilePath(sbSource.toString());

            if (!origin.fileExists(sbSource.toString())) {
                throw new FileNotFoundException(LABEL_FILE
                        + sourceConfig.getFilePath() + LABEL_NOT_FOUND);
            }

            try (File oldFile = origin.openFile(sourceConfig.getFilePath(),
                    EnumSet.of(AccessMask.FILE_READ_DATA), null,
                    SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN,
                    EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE))) {

                SambaConfig destinationConfig = getParametersFromURL(destinationPath);
                Session destinationSession = getAuthentication(
                        destinationConfig, client);
                DiskShare destination = (DiskShare) destinationSession
                        .connectShare(destinationConfig.getShare());

                if (!destination.folderExists(destinationConfig.getPath()))
                    destination.mkdir(destinationConfig.getPath());

                StringBuilder sbDestination = new StringBuilder();
                sbDestination.append(destinationConfig.getPath());
                if (destinationPath.lastIndexOf("/") != destinationPath
                        .length() - 1)
                    sbDestination.append("/");
                sbDestination.append(sourcePath);

                String target = sbDestination.toString();

                File newFile = destination.openFile(target,
                        EnumSet.of(AccessMask.FILE_WRITE_DATA), null,
                        SMB2ShareAccess.ALL, null, null);

                copyFile(oldFile, newFile);

                boolean fileExists = destination.fileExists(target);

                if (fileExists) {
                    origin.rm(sourceConfig.getFilePath());
                }
                origin.close();
                destination.close();

                return fileExists;

            }

        } catch (Exception e) {
            log.error("Failed to move: ".concat(e.getMessage()));
            return false;
        }
    }

    @Override
    public boolean delete(String resource) {

        try (SMBClient client = new SMBClient()) {

            SambaConfig sambaConfig = getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig, client);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig
                    .getShare());

            if (!share.fileExists(sambaConfig.getFilePath())) {
                throw new FileNotFoundException(LABEL_FILE
                        + sambaConfig.getFilePath() + LABEL_NOT_FOUND);
            }

            share.rm(sambaConfig.getFilePath());
            boolean fileExists = share.fileExists(sambaConfig.getFilePath());
            share.close();

            return !fileExists;
        } catch (Exception e) {
            log.error("Failed to delete: ".concat(e.getMessage()));
            return false;
        }
    }

    /**
     * This function returns a File object to be used in all methods which needs
     * read information from a source file
     *
     * @param share
     * @param sambaConfig
     * @return
     */
    private static File getFileToRead(DiskShare share, SambaConfig sambaConfig) {
        return share.openFile(sambaConfig.getFilePath(),
                EnumSet.of(AccessMask.FILE_READ_DATA), null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null);
    }

    /**
     * This function generates a session in order to connect this app to samba
     * on a remote server Requires an object with connection params
     *
     * @param params
     * @return
     * @throws IOException
     * @throws Exception
     */
    private static Session getAuthentication(SambaConfig params,
                                             SMBClient client) throws IOException {
        Connection connection = client.connect(params.getHost());
        AuthenticationContext ac = new AuthenticationContext(params.getUser(),
                params.getPassword().toCharArray(), params.getDomain());
        return connection.authenticate(ac);
    }

    /**
     * This method copies all content from a source file to a destination file,
     * and after all it deletes the original file Works with move function
     *
     * @param source
     * @param destination
     * @throws IOException
     */
    private static void copyFile(File source, File destination)
            throws IOException {
        byte[] buffer = new byte[8 * BUFFER_SIZE];
        try (InputStream in = source.getInputStream()) {
            try (OutputStream out = destination.getOutputStream()) {
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    /**
     * This function takes all the URL parameters and puts them into a POJO
     * class to connect to a remote server
     *
     * @param url
     * @return
     */
    private static SambaConfig getParametersFromURL(String url) {
        SambaConfig samba = new SambaConfig();
        String newURL = url.replace("smb://", "");

        if (newURL.contains(":") && newURL.contains("$")) {
            String[] splitData = newURL.split(CONST_SPLIT);

            if (splitData.length > 0 && splitData.length == 5) {
                samba.setDomain(splitData[0]);
                samba.setUser(splitData[1]);
                samba.setPassword(splitData[2]);
                samba.setHost(splitData[3]);
                samba.setPath(splitData[4]);
            }
        } else {
            String[] splitData = newURL.split(CONST_SPLIT_SECOND);
            if (splitData.length > 0 && splitData.length == 4) {
                samba.setDomain(splitData[0]);
                samba.setUser(splitData[1]);
                samba.setPassword(splitData[2]);

                int firstSlashIndex = firstIndexOf(splitData[3], '/');

                String host = splitData[3].substring(0, firstSlashIndex);

                String missing = splitData[3].substring(firstSlashIndex + 1,
                        splitData[3].length());

                int secondSlashIndex = firstIndexOf(missing, '/');
                String share = missing.substring(0, secondSlashIndex);
                String path = missing.substring(secondSlashIndex,
                        missing.length());

                samba.setHost(host);
                samba.setShare(share);
                samba.setPath(path);
            }
        }

        if (samba.getHost().contains("/")) {
            String[] splitHost = samba.getHost().split("/");
            samba.setHost(splitHost[0]);
            samba.setShare(splitHost[1]);
        }

        if (samba.getPath().contains(".")) {
            samba.setFilePath(samba.getPath());

            int lastSlashIndex = samba.getPath().lastIndexOf("/");
            String newPath = samba.getPath().substring(0, lastSlashIndex);
            samba.setPath(newPath);
        }

        if (url.contains("$")) {
            samba.setShare(samba.getShare() + "$");
        }
        return samba;
    }

    private static int firstIndexOf(String word, char letter) {
        for (int i = 0; i < word.toCharArray().length; i++) {
            if (word.charAt(i) == letter)
                return i;
        }
        return 0;
    }
}
