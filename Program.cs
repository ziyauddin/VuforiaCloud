using Newtonsoft.Json;
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;

namespace VuforiaCloud
{
    public class Program
    {
        private static string access_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        private static string secret_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        private static string url = @"https://vws.vuforia.com";
        private static string targetName = "YachtDev";

        // Get the image from bin folder 
        private static string imageLocation = Directory.GetCurrentDirectory() + "/YachtDev.png";
        private static byte[] requestBytesArray;
        static void Main(string[] args)
        {
            RootObject result = PostNewTargets();
        }
        public static RootObject PostNewTargets()
        {
            WebResponse response = null;
            RootObject rootObject = new RootObject();

            try
            {
                string requestPath = "/targets";
                string serviceURI = url + requestPath;
                string httpAction = "POST";
                string contentType = "application/json";
                string date = string.Format("{0:r}", DateTime.Now.ToUniversalTime());

                var imageFile = File.Open(imageLocation, FileMode.Open);
                byte[] image;
                using (var br = new BinaryReader(imageFile))
                    image = br.ReadBytes((int)imageFile.Length);

                string metadataStr = "YachtDev";
                byte[] metadata = ASCIIEncoding.ASCII.GetBytes(metadataStr);
                PostNewTrackableRequest model = new PostNewTrackableRequest();
                model.name = targetName;
                model.width = 8.0f;
                model.image = Convert.ToBase64String(image);
                model.active_flag = true;
                model.application_metadata = Convert.ToBase64String(metadata);

                var serializer = new JavaScriptSerializer();
                string requestBody = serializer.Serialize(model);
                HttpWebRequest httpWReq = (HttpWebRequest)HttpWebRequest.Create(serviceURI);

                //If Proxy Authentication Required
                IWebProxy proxy = httpWReq.Proxy;
                if (proxy != null)
                {
                    //Proxy ip address with port
                    string proxyuri = "http://000.000.000.000:8080/";
                    httpWReq.UseDefaultCredentials = true;
                    httpWReq.Proxy = new WebProxy(proxyuri, false);
                    httpWReq.Proxy.Credentials = System.Net.CredentialCache.DefaultCredentials;
                }
                //
                httpWReq.Method = httpAction;
                MethodInfo priMethod = httpWReq.Headers.GetType().GetMethod("AddWithoutValidate", BindingFlags.Instance | BindingFlags.NonPublic);
                priMethod.Invoke(httpWReq.Headers, new[] { "Date", DateTime.UtcNow.ToString("ddd, dd MMM yyy HH:mm:ss") + " GMT" });
                //request.Headers.Add("Date", DateTime.UtcNow.ToString("ddd, dd MMM yyy HH:mm:ss") + " GMT");
                httpWReq.ContentType = contentType;
                httpWReq.UseDefaultCredentials = true;
                httpWReq.PreAuthenticate = true;
                httpWReq.Credentials = CredentialCache.DefaultCredentials;
                MD5 md5 = MD5.Create();
                var contentMD5bytes = md5.ComputeHash(Encoding.ASCII.GetBytes(requestBody));
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < contentMD5bytes.Length; i++)
                {
                    sb.Append(contentMD5bytes[i].ToString("x2"));
                }

                string contentMD5 = sb.ToString();

                string stringToSign = string.Format("{0}\n{1}\n{2}\n{3}\n{4}", httpAction, contentMD5, contentType, date, requestPath);

                HMACSHA1 sha1 = new HMACSHA1(Encoding.ASCII.GetBytes(secret_key));
                byte[] sha1Bytes = Encoding.ASCII.GetBytes(stringToSign);
                MemoryStream stream = new MemoryStream(sha1Bytes);
                byte[] sha1Hash = sha1.ComputeHash(stream);
                string signature = Convert.ToBase64String(sha1Hash);
                httpWReq.Headers.Add("Authorization", string.Format("VWS {0}:{1}", access_key, signature));

                var streamWriter = httpWReq.GetRequestStream();
                byte[] buffer = Encoding.ASCII.GetBytes(requestBody);
                requestBytesArray = buffer;
                streamWriter.Write(buffer, 0, buffer.Length);
                streamWriter.Flush();
                streamWriter.Close();

                response = httpWReq.GetResponse();

                Stream receiveStream = response.GetResponseStream();
                StreamReader sr = new StreamReader(receiveStream, Encoding.UTF8);
                string responseData = sr.ReadToEnd();
                response.Close();
                sr.Close();
                rootObject = JsonConvert.DeserializeObject<RootObject>(responseData);
            }
            catch (Exception e)
            {
                var message = e.Message;
                var innerException = e.InnerException;
            }
            return rootObject;
        }
        /// <summary>
        /// Method holds the certificates
        /// </summary>
        /// <param name="sender">Sender Id</param>
        /// <param name="certificate">Certificate object</param>
        /// <param name="chain">Chain object</param>
        /// <param name="sslPolicyErrors">policy errors</param>
        /// <returns>returns true</returns>
        public static bool ValidateServerCertificate(
                                                      object sender,
                                                      X509Certificate certificate,
                                                      X509Chain chain,
                                                      SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
    public class RootObject
    {
        public string result_code { get; set; }
        public string transaction_id { get; set; }
        public string target_id { get; set; }
    }
    public class PostNewTrackableRequest
    {
        public string name;
        public float width;
        public string image;
        public bool active_flag;
        public string application_metadata;
    }
}
