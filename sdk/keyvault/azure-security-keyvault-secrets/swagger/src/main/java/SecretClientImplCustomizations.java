// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

import com.azure.autorest.customization.ClassCustomization;
import com.azure.autorest.customization.Customization;
import com.azure.autorest.customization.LibraryCustomization;
import com.azure.autorest.customization.PackageCustomization;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.Modifier;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.Type;
import org.slf4j.Logger;

import java.util.List;

/**
 * Contains customizations for Azure Key Vault's swagger code generation.
 */
public class SecretClientImplCustomizations extends Customization {
    @Override
    public void customize(LibraryCustomization libraryCustomization, Logger logger) {
        customizeClientImpls(libraryCustomization.getPackage("com.azure.security.keyvault.secrets.implementation"));
    }

    private static void customizeClientImpls(PackageCustomization packageCustomization) {
        customizeSecretClientImpl(packageCustomization.getClass("SecretClientImpl"));
    }

    private static void customizeSecretClientImpl(ClassCustomization classCustomization) {
        classCustomization.customizeAst(ast -> {
            ClassOrInterfaceDeclaration clazz = ast.getClassByName(classCustomization.getClassName()).get();
            List<MethodDeclaration> methods = clazz.getMethodsByName("setSecretWithResponseAsync");
            methods.addAll(clazz.getMethodsByName("setSecretAsync"));
            methods.addAll(clazz.getMethodsByName("setSecretWithResponse"));
            methods.addAll(clazz.getMethodsByName("setSecret"));

            JavaParser javaParser = new JavaParser();
            ClassOrInterfaceType stringType = javaParser.parseClassOrInterfaceType("String").getResult().get();

            Parameter contentTypeParameter = new Parameter(stringType, "contentType");
            Parameter stringContentTypeParameter = new Parameter(stringType, "stringContentType");

            methods.forEach(method -> {
                method.replace(contentTypeParameter, stringContentTypeParameter);
            });

            clazz.addMethod("fromUrl", Modifier.Keyword.PUBLIC, Modifier.Keyword.STATIC)
                .setType("KeyVaultRoleScope")
                .addParameter("String", "url")
                .setJavadocComment(StaticJavaParser.parseJavadoc(joinWithNewline(
                    "/**",
                    " * Creates of finds a {@link KeyVaultRoleScope} from its string representation.",
                    " *",
                    " * @param url A string representing a URL containing the name of the scope to look for.",
                    " * @return The corresponding {@link KeyVaultRoleScope}.",
                    " * @throws IllegalArgumentException If the given {@code url} is malformed.",
                    " */"
                )))
                .setBody(StaticJavaParser.parseBlock(joinWithNewline(
                    "{",
                    "try {",
                    "    return fromString(new URL(url).getPath());",
                    "} catch (MalformedURLException e) {",
                    "    throw new IllegalArgumentException(e);",
                    "}",
                    "}"
                )));
        });
    }

    private static String joinWithNewline(String... lines) {
        return String.join("\n", lines);
    }
}
