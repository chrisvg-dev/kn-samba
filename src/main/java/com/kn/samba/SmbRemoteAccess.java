package com.kn.samba;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileDirectoryQueryableInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import org.apache.log4j.Logger;

import java.io.*;
import java.nio.charset.Charset;
import java.util.EnumSet;
import java.util.Properties;

public class SmbRemoteAccess {
    private static final Logger log = Logger.getLogger( SmbRemoteAccess.class );
    protected static final String LINE_SEPARATOR = System.getProperty("line.separator");
    private static final int BUFFER_SIZE = 1024;

    /**
     * Como la librería de SMBJ necesita de todas estas clases para abrir una conexión con Samba se manejan como variables globales
     * ya que de no utilizarse así en muchas ocasiones pueden quedar abiertos alguns flujos de información, incluso llegar a repetirse en muchas ocasiones.
     * Con estas variables globales se agregan 2 métodos nuevos: openConnection y closeConnection
     */
    private SMBClient client; // Se utiliza para abrir la conexión al servidor de samba
    private Connection connection; // Se almacena la información de la conexión activa
    private Session session; // Genera la sesión necesaria para la transferencia de archivos
    private DiskShare diskShare; // Abre conexión con el disco al que se quiere acceder y brinda la información necesaria de los archivos

    private void openConnection(SmbProperties config) throws IOException {
        this.client = new SMBClient();
        this.connection = client.connect(config.getHost());
        AuthenticationContext authenticationContext = new AuthenticationContext( config.getUser(), config.getPassword().toCharArray(), config.getHost() );
        this.session = connection.authenticate(authenticationContext);
        this.diskShare = (DiskShare) session.connectShare(config.getShare());
    }

    private void closeConnection() throws IOException {
        this.diskShare.close();
        this.session.close();
        this.connection.close();
        this.client.close();
    }
    /**  */

    private File getFileForReading(String filePath) {
        return this.diskShare.openFile(filePath,
                EnumSet.of(AccessMask.FILE_READ_DATA),
                null,
                SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_OPEN,
                null);
    }

    private File getFileForWriting(String filePath) {
        return this.diskShare.openFile(filePath,
                EnumSet.of(AccessMask.FILE_WRITE_DATA),
                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_SUPERSEDE,
                EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));
    }

    public String read(String resource) {
        try  {
            SmbProperties config = getParametersFromURL(resource);
            this.openConnection(config);
            File file = getFileForReading(config.getFilePath());

            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(file.getInputStream()));

            StringBuilder result = new StringBuilder();
            String line = "";
            while ((line = bufferedReader.readLine()) != null) {
                result.append(line).append(LINE_SEPARATOR);
            }

            file.close();
            bufferedReader.close();

            this.closeConnection();

            return result.toString();
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    public byte[] readBinary(String resource) {
        try {
            int bytesRead = 0;
            SmbProperties config = getParametersFromURL(resource);
            this.openConnection(config);

            File file = getFileForReading(config.getFilePath());

            byte[] buffer = new byte[BUFFER_SIZE];
            BufferedInputStream bi = new BufferedInputStream(file.getInputStream());
            ByteArrayOutputStream bao = new ByteArrayOutputStream(BUFFER_SIZE);

            while ((bytesRead = bi.read(buffer)) != -1) {
                bao.write(buffer, 0, bytesRead);
            }

            bi.close();
            file.close();

            this.closeConnection();

            return bao.toByteArray();
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    public boolean write(String resource, String lines, String encoding) {
        try {
            SmbProperties config = getParametersFromURL(resource);
            this.openConnection(config);
            File file = getFileForWriting(config.getFilePath());

            OutputStream out = file.getOutputStream();
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, Charset.forName(encoding)));

            writer.write(lines);
            writer.flush();

            out.close();
            file.close();

            boolean created = this.diskShare.fileExists(config.getFilePath());
            this.closeConnection();

            return created;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return false;
    }

    public boolean write(String resource, byte[] lines) {
        try {
            SmbProperties config = getParametersFromURL(resource);
            this.openConnection(config);
            File file = getFileForWriting(config.getFilePath());

            OutputStream os = file.getOutputStream();
            os.write(lines);
            os.flush();

            os.close();
            file.close();

            this.closeConnection();

            return true;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return false;
    }

    public String[] list(String resource, String filter) {
        try {
            SmbProperties config = getParametersFromURL(resource);
            this.openConnection(config);

            String filterFormat = "*." + filter;

            String[] files = this.diskShare.list(config.getPath(), filterFormat).stream()
                    .map( FileDirectoryQueryableInformation::getFileName )
                    .toArray(String[]::new);

            this.closeConnection();
            return files;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    public boolean move(String resource, String sourcePath, String destinationPath) {
        try {
            SmbProperties originConfig = getParametersFromURL(resource);
            this.openConnection(originConfig);

            String oldFilePath = originConfig.getPath() + "/" + sourcePath;
            String newFilePath = originConfig.getPath() + "/" + destinationPath;

            File origin = getFileForReading(originConfig.getPath() + "/" + sourcePath);
            File destination = getFileForWriting( originConfig.getPath() + "/" + destinationPath );

            copyFile(origin, destination);

            origin.close();
            destination.close();

            boolean moved = this.diskShare.fileExists(newFilePath);

            if (moved) this.diskShare.rm(oldFilePath);

            this.closeConnection();

            return moved;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return false;
    }

    public boolean delete(String resource) {
        try {
            SmbProperties config = getParametersFromURL(resource);
            this.openConnection(config);

            this.diskShare.rm(config.getFilePath());

            boolean isDeleted = !this.diskShare.fileExists(config.getFilePath());
            this.closeConnection();

            return isDeleted;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return false;
    }
    private static void copyFile(File source, File destination) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        try (InputStream in = source.getInputStream()) {
            try (OutputStream out = destination.getOutputStream()) {
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    private static SmbProperties getParametersFromURL(String resource) throws IOException {
        String path = "src/main/resources/application.properties";
        try(InputStream inputStream = new FileInputStream(path)){
            Properties properties = new Properties();
            properties.load(inputStream);

            SmbProperties config = new SmbProperties();
            config.setUser( properties.getProperty("kn.smbj.user") );
            config.setPassword( properties.getProperty("kn.smbj.password") );
            config.setDomain( properties.getProperty("kn.smbj.domain") );
            config.setHost( properties.getProperty("kn.smbj.host") );
            config.setShare( properties.getProperty("kn.smbj.shared") );
            config.setPath( properties.getProperty("kn.smbj.path") );
            config.setFilePath( properties.getProperty("kn.smbj.filePath") );
            return config;
        }
    }
}
