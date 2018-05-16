#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/errno.h> 
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>  
#include <asm/page.h>  
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <asm/string.h>

asmlinkage int (*exopen)(const char *pathname, int flags);
unsigned long *syscall_table;
char* ptrFilePath;

module_param(syscall_table, ulong, S_IRUGO);
module_param(ptrFilePath, charp, S_IRUGO);

int set_addr_rw(long unsigned int _addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(_addr, &level);

    if (pte->pte &~ _PAGE_RW) 
        pte->pte |= _PAGE_RW;
}

int set_addr_ro(long unsigned int _addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(_addr, &level);

    pte->pte = pte->pte &~_PAGE_RW;
}

asmlinkage int nopen(const char *pathname, int flags) {

    struct task_struct *task = current; // getting global current pointer
    if(strstr(pathname, "media") != NULL) {
        printk(KERN_ALERT "OPEN:PROCESS:[%s]\tPID:[%d]\nPATH:[%s]\n",task->comm, task->pid, pathname);
    }
	    
    return (*exopen)(pathname, flags);
}

static int USBsniffer_init(void) {

    printk(KERN_ALERT "\nINIT: USBsniffer v0.1 \n");

    set_addr_rw((unsigned long)syscall_table);
    exopen = (void *)syscall_table[__NR_open];
    syscall_table[__NR_open] = nopen;  

    return 0;
}

static void USBsniffer_exit(void) {

    syscall_table[__NR_open] = exopen;  
    set_addr_ro((unsigned long)syscall_table);
    printk(KERN_ALERT "EXIT: USBsniffer v0.1 \n");
    return;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("straceX");
MODULE_DESCRIPTION("Monitoring USB File Traffic and Reporting USB Devices Activity");
module_init(USBsniffer_init);
module_exit(USBsniffer_exit);
