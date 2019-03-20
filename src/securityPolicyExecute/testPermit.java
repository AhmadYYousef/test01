package securityPolicyExecute;


 
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.balana.Balana;
import org.wso2.balana.PDP;
import org.wso2.balana.PDPConfig;
import org.wso2.balana.ParsingException;
import org.wso2.balana.ctx.AbstractResult;
import org.wso2.balana.ctx.AttributeAssignment;
import org.wso2.balana.ctx.ResponseCtx;
import org.wso2.balana.finder.AttributeFinder;
import org.wso2.balana.finder.AttributeFinderModule;
import org.wso2.balana.finder.impl.FileBasedPolicyFinderModule;
import org.wso2.balana.xacml3.Advice;

import javax.xml.parsers.DocumentBuilderFactory;

import java.io.ByteArrayInputStream; 
import java.io.File;
import java.io.IOException;
import java.util.*;


public class testPermit {

	 private static Balana balana;

	 

	 public static void main(String[] args){
 
		//	System.out.print("Test");
			
 

	        String subjectId ="C80001";

	        String subjectName ="Hadeel Neama";

	        String subjectDep ="HR";

	        String subjectJob ="Employee";
 
	        String resource ="Employee";
	        //printDescription(); 

	       // initData();
	        
	        initBalana();

	        String request = createXACMLRequest( subjectId,subjectName , subjectDep, subjectJob,resource);
	        PDP pdp = getPDPNewInstance();

	        System.out.println("\n======================== XACML Request ====================");
	        System.out.println(request);
	        System.out.println("===========================================================");

	        String response = pdp.evaluate(request); 
	        System.out.println("\n======================== XACML Response ===================");
	        System.out.println(response);
	        System.out.println("===========================================================");

	        try {
	            ResponseCtx responseCtx = ResponseCtx.getInstance(getXacmlResponse(response));
	            AbstractResult result  = responseCtx.getResults().iterator().next();
	            if(AbstractResult.DECISION_PERMIT == result.getDecision()){
	                System.out.println("\n Result is \"Permit\"   \n");
	            } else {
	            	System.out.println("\n Result is \"Deny\"   \n");
	                List<Advice> advices = result.getAdvices();
	                for(Advice advice : advices){
	                    List<AttributeAssignment> assignments = advice.getAssignments();
	                    for(AttributeAssignment assignment : assignments){
	                        System.out.println("Advice :  " + assignment.getContent() +"\n\n");
	                    }
	                }
	            }
	        } catch (ParsingException e) {
	            e.printStackTrace();
	        }

	        
	      
			//System.out.print("Test2");
			
	 }
	 
	 private static void initBalana() {
		 
		         try{
		             // using file based policy repository. so set the policy location as system property
		             String policyLocation = (new File(".")).getCanonicalPath() + File.separator + "resources";
		             System.setProperty(FileBasedPolicyFinderModule.POLICY_DIR_PROPERTY, policyLocation);
		         } catch (IOException e) {
		             System.err.println("Can not locate policy repository");
		         }
		         // create default instance of Balana
		         balana = Balana.getInstance();
		     }

	 //////////////////////getPDPNewInstance
	 public static String createXACMLRequest( String userID, String userName, String subjectDep , String subjectJob  , String resource){
				          
		        
		        return "<Request xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" CombinedDecision=\"false\" ReturnPolicyIdList=\"false\">\n" +
		                "<Attributes Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\">\n" +
		                "<Attribute AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" IncludeInResult=\"false\">\n" +
		                "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">"+"read"+"</AttributeValue>\n" +
		                "</Attribute>\n" +
		                "</Attributes>\n" +
 
		                "<Attributes Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\">\n" +
		                "<Attribute AttributeId=\"urn:oasis:names:tc:xacml:1.0:subject:subject-id\" IncludeInResult=\"false\">\n" +
		                "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + userID +"</AttributeValue>\n" +
		                "</Attribute>\n" +
		                "</Attributes>\n" +

		                "<Attributes Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\">\n" +
		                
		                "<Attribute AttributeId=\"subjectName\" IncludeInResult=\"false\">\n" +
		                "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + userName +"</AttributeValue>\n" +
		                "</Attribute>\n" +
		                "</Attributes>\n" +

		                "<Attributes Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\">\n" +
		                
		                "<Attribute AttributeId=\"subjectDep\" IncludeInResult=\"false\">\n" +
		                "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + subjectDep +"</AttributeValue>\n" +
		                "</Attribute>\n" +
		                "</Attributes>\n" +

		                "<Attributes Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\">\n" +
		                 "<Attribute AttributeId=\"subjectJob\" IncludeInResult=\"false\">\n" +
		                "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + subjectJob +"</AttributeValue>\n" +
		                "</Attribute>\n" +
		                "</Attributes>\n" +

		              
		                
		                "<Attributes Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:resource\">\n" +
		                "<Attribute AttributeId=\"subjectJob\" IncludeInResult=\"false\">\n" +
		                "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + resource + "</AttributeValue>\n" +
		                "</Attribute>\n" +
		                "</Attributes>\n" +
		                
		                          
		                "</Request>";


		    }
	 
	 
	 //////////////////////getPDPNewInstance
	 private static PDP getPDPNewInstance(){

	        PDPConfig pdpConfig = balana.getPdpConfig();

	        // registering new attribute finder. so default PDPConfig is needed to change
	        AttributeFinder attributeFinder = pdpConfig.getAttributeFinder();
	        List<AttributeFinderModule> finderModules = attributeFinder.getModules();
	        finderModules.add(new SampleAttributeFinderModule());
	        attributeFinder.setModules(finderModules);

	        return new PDP(new PDPConfig(attributeFinder, pdpConfig.getPolicyFinder(), null, true));
	    }
	    
	    //////////////////////getXacmlResponse
	    public static Element getXacmlResponse(String response) {

	        ByteArrayInputStream inputStream;
	        DocumentBuilderFactory dbf;
	        Document doc;

	        inputStream = new ByteArrayInputStream(response.getBytes());
	        dbf = DocumentBuilderFactory.newInstance();
	        dbf.setNamespaceAware(true);

	        try {
	            doc = dbf.newDocumentBuilder().parse(inputStream);
	        } catch (Exception e) {
	            System.err.println("DOM of request element can not be created from String");
	            return null;
	        } finally {
	            try {
	                inputStream.close();
	            } catch (IOException e) {
	               System.err.println("Error in closing input stream of XACML response");
	            }
	        }
	        return doc.getDocumentElement();
	    }    

}
