//
//  ESViewController.h
//  Text Signature
//
//  Created by test on 13-9-3.
//  Copyright (c) 2013年 test. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ESViewController : UIViewController<UITextFieldDelegate>

@property (weak, nonatomic) IBOutlet UITextField *UserPin;
@property (weak, nonatomic) IBOutlet UITextView *TextField;
@property (weak, nonatomic) IBOutlet UITextView *SignatureResult;
@property (weak, nonatomic) IBOutlet UITextField *tokenLabel;
@property (weak, nonatomic) IBOutlet UITextField *pinRetryCount;

- (IBAction)StartSignture:(id)sender;
@end
