//
//  ESViewController.m
//  Text Signature
//
//  Created by test on 13-9-3.
//  Copyright (c) 2013年 test. All rights reserved.
//

#import "ESViewController.h"
#include "cryptoki_linux.h"
#include "auxiliary.h"

@interface ESViewController ()
{
    AUX_FUNC_LIST_PTR pAuxFunc;
    BOOL hasDevice_;
    BOOL isRunning;
}

@property (assign,atomic) BOOL hasDevice;

@end

@implementation ESViewController

@synthesize hasDevice = hasDevice_;

- (IBAction)touchBackground:(id)sender
{
    [self.view endEditing:YES];
    
    if (self.view.frame.origin.y < 0)
    {
        [UIView animateWithDuration:0.4f animations:^{
            CGRect rect = self.view.frame;
            rect.origin.y = 0.0f;
            [self.view setFrame:rect];
        }];
    }
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    self.TextField.layer.borderColor = [[UIColor blackColor] CGColor];
    self.TextField.layer.borderWidth = 1.0f;
    
    self.SignatureResult.layer.borderColor = [[UIColor blackColor] CGColor];
    self.SignatureResult.layer.borderWidth = 1.0f;
    
    pAuxFunc = NULL;
    hasDevice_ = NO;
    isRunning = YES;
    
    NSOperationQueue *queue = [[NSOperationQueue alloc] init];
    queue.maxConcurrentOperationCount = 2;
    [queue addOperationWithBlock:^{
        [self initLibrary];
    }];
}

- (void) initLibrary
{
    CK_RV rv = CKR_OK;
    rv = C_Initialize(NULL_PTR);
    if (rv != CKR_OK)
    {
        [self showMessage:@"Info" message:@"PKCS11 Library initialize failed!"];
        return;
    }
    
    rv = E_GetAuxFunctionList(&pAuxFunc);
    if (rv != CKR_OK)
    {
        [self showMessage:@"Info" message:@"PKCS11 Library initialize failed!"];
        return;
    }
    
    CK_ULONG currentCount = 0;
    do
    {
        CK_ULONG ulCount = 0;
        rv = C_GetSlotList(true, NULL, &ulCount);
        NSLog(@"slot count:%ld",ulCount);
        if (rv != CKR_OK)
        {
            break;
        }
        
        if (ulCount > currentCount)
        {
            currentCount = ulCount;
            self.hasDevice = YES;
        }
        else if (ulCount < currentCount)
        {
            currentCount = ulCount;
            self.hasDevice = NO;
        }
        
        sleep(1);
        
    } while (isRunning);
}

- (void) showMessage:(NSString*) title message:(NSString*)message
{
    [[NSOperationQueue mainQueue] addOperationWithBlock:^{
        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:title message:message delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil];
        [alertView show];
    }];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
}

- (void)textFieldDidBeginEditing:(UITextField *)textField
{
    if (textField.tag == 1000)
    {
        [UIView animateWithDuration:0.4f animations:^{
            CGRect rect = self.view.frame;
            rect.origin.y -= 160.0f;
            [self.view setFrame:rect];
        }];
    }
}

- (IBAction)StartSignture:(id)sender
{
    NSString * nsUserPin = _UserPin.text;
    if(nsUserPin.length <= 0)
    {
        [self showMessage:@"Info" message:@"User pin cannot be empty!"];
        _UserPin.text = @"";
        return;
        
    }
    
    NSString* signingString = _TextField.text;
    if (signingString.length <= 0)
    {
        [self showMessage:@"Info" message:@"Signing data cannot be empty!"];
        _UserPin.text = @"";
        return;
    }
    
    if (!self.hasDevice)
    {
        [self showMessage:@"info" message:@"No availiable Device to use Or the device is loading"];
        return;
    }
    
    //Signature
    //------------------
        
    CK_RV rv = 0;
    CK_SLOT_ID slotID;
    CK_ULONG vc = 1;
    rv = C_GetSlotList(TRUE, &slotID, &vc);
    if(rv != CKR_OK)
	{
		[self showMessage:@"info" message:@"No availiable Device to use"];
		return;
	}

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	rv = C_OpenSession( slotID , CKF_RW_SESSION | CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&session);
	if(rv != CKR_OK)
	{
        [self showMessage:@"info" message:@"Failed Open Session"];
		return;
	}
    
	//Locgin
	rv = C_Login(session,CKU_USER,(CK_CHAR_PTR)[nsUserPin UTF8String],[nsUserPin length]);
    
	if(rv != CKR_OK)
	{
        [self showMessage:@"info" message:@"Failed login"];
		return;
	}
    
    //data
	CK_BBOOL bTrue = true;
	CK_OBJECT_CLASS class1 = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE objTemplate[] =
	{
		{CKA_CLASS, &class1, sizeof(class1)},
		{CKA_TOKEN, &bTrue, sizeof(bTrue)}
	};
    
	rv  = C_FindObjectsInit(session, objTemplate, 2);
	if(rv != CKR_OK)
	{
        [self showMessage:@"info" message:@"Find Object Init failed!"];
		return;
	}
    
	CK_ULONG count =0;
	CK_OBJECT_HANDLE hObjPrivate;

    rv = C_FindObjects(session, &hObjPrivate, 1, &count);
    if(rv != CKR_OK || (count != 1))
    {
        [self showMessage:@"info" message:@"Find object failed!"];
        C_FindObjectsFinal(session);
        return;
    }
    
	C_FindObjectsFinal(session);

	CK_MECHANISM signMech = {CKM_SHA1_RSA_PKCS,NULL_PTR,0};
	CK_BYTE tmpResult[512]={0};//BYTE;
	CK_ULONG tmpResultLength =sizeof(tmpResult)/sizeof(CK_BYTE);
    
	rv = C_SignInit(session,&signMech,hObjPrivate);
	if(rv != CKR_OK)
	{
        [self showMessage:@"info" message:[NSString stringWithFormat:@"CSign Init Failed. error : %lX",rv]];
		return;
	}
    
    
	rv = C_Sign(session,(CK_BYTE_PTR)([signingString UTF8String]),signingString.length,tmpResult,&tmpResultLength);
	if(rv != CKR_OK)
	{
        [self showMessage:@"info" message:[NSString stringWithFormat:@"CSign Failed. error : %lX",rv]];
		return;
	}
    C_CloseSession(session);
    
    char temp[2048] = {0};
    int span = 0;
    for(int i = 0; i < tmpResultLength; i++)
    {
        sprintf(temp+span,"%02X ", tmpResult[i]);
        span += 3;
        if ((i+1) % 8 == 0)
        {
            sprintf(temp+span,"\n");
            span++;
        }
        
    }
    _SignatureResult.text  = [NSString stringWithCString:temp encoding:NSASCIIStringEncoding];
    [self showMessage:@"info" message:@"Sign data Successfully"];
}

- (IBAction)changeTokenLabel:(id)sender
{
    NSString* labelString = self.tokenLabel.text;
    if (labelString.length <= 0)
    {
        [self showMessage:@"Info" message:@"New Token Label cannot be empty!"];
        _UserPin.text = @"";
        return;
    }
    
    if (!self.hasDevice)
    {
        [self showMessage:@"info" message:@"No availiable Device to use Or the device is loading"];
        return;
    }
    
    CK_RV rv = 0;
    CK_SLOT_ID slotID;
    CK_ULONG vc = 1;
    rv = C_GetSlotList(TRUE, &slotID, &vc);
    if(rv != CKR_OK)
	{
		[self showMessage:@"info" message:@"No availiable Device to use"];
		return;
	}
    rv = ((EP_SetTokenLabel)pAuxFunc->pFunc[EP_SET_TOKEN_LABEL])(slotID,NULL, NULL , NULL, (CK_UTF8CHAR_PTR)[labelString UTF8String]);
    if (rv != CKR_OK)
    {
        [self showMessage:@"info" message:@"Change Token Label failed!"];
        return;
    }
    
    [self showMessage:@"info" message:@"Change Token Label Successfully!"];
}

- (IBAction)getPinRetryCount:(id)sender
{
    if (!self.hasDevice)
    {
        [self showMessage:@"info" message:@"No availiable Device to use Or the device is loading"];
        return;
    }
    
    CK_RV rv = 0;
    CK_SLOT_ID slotID;
    CK_ULONG vc = 1;
    rv = C_GetSlotList(TRUE, &slotID, &vc);
    if(rv != CKR_OK)
	{
		[self showMessage:@"info" message:@"No availiable Device to use"];
		return;
	}
    
    AUX_PIN_INFO pinInfo = {0};
    rv = ((EP_GetPinInfo)pAuxFunc->pFunc[EP_GET_PIN_INFO])(slotID, &pinInfo);
    if (rv != CKR_OK)
    {
        [self showMessage:@"info" message:@"Get Pin Info Failed!"];
        return;
    }
    
    [self.pinRetryCount setText:[NSString stringWithFormat:@"%d",pinInfo.bUserPinCurCounter]];
    
    [self showMessage:@"info" message:@"Get Pin Info Successfully"];
}

- (void)dealloc
{
}

@end
