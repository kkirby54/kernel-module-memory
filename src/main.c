#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/uaccess.h>

#define PROC_NAME "hw2"
#define PERIOD_DEFAULT 5;   // DEFAULT: 5 seconds

MODULE_AUTHOR("Kim, Minhyup");
MODULE_LICENSE("GPL v2");

// passing argument "period"
int period = PERIOD_DEFAULT;
module_param(period, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(period, "Period for investigate");

struct proc_dir_entry* parent;  // parent name = "hw2"
static const struct proc_ops hw2_proc_fops;
int try_count = 0;

// for process pid name(ex. "1", "3", "1234")
char* name = "NULL";

void do_job(void);
void printBaseInfo(struct seq_file* s, struct task_struct* currProcess);
void printf_bar(struct seq_file* s);
void printf_code(struct seq_file* s, struct task_struct* currProcess);
void printf_data(struct seq_file* s, struct task_struct* currProcess);
void printf_heap(struct seq_file* s, struct task_struct* currProcess);
void printf_stack(struct seq_file* s, struct task_struct* currProcess);

static void printAddressAndValue(struct seq_file* s, struct task_struct* currProcess, unsigned long vaddr);

/**
 * This function is called for each "step" of a sequence
 *
 */
static int hw2_seq_show(struct seq_file *s, void *v)
{
    struct task_struct* task;
    long id;

    // convert string to int
    kstrtol(name, 10, &id);
    task = get_pid_task(find_get_pid((int) id), PIDTYPE_PID);

    // if no process, do nothing
    if (NULL == task){
        seq_printf(s, "NO PROCESS!\n");
    }
    else{
        printBaseInfo(s, task);
    }

    loff_t *spos = (loff_t*) v;
    return 0;
}

// for traverse Processes
#define next_task(p) \
        list_entry_rcu((p)->tasks.next, struct task_struct, tasks)

#define for_each_process(p) \
        for (p = &init_task ; (p = next_task(p)) != &init_task ; )


void printBaseInfo(struct seq_file* s, struct task_struct* currProcess){
    printf_bar(s);
    seq_printf(s, "Student name(ID): %s(%s)\n", "Kim, Minhyup", "2017127046");
    seq_printf(s, "Process name(ID): %s(%d)\n", currProcess->comm, currProcess->pid);
    seq_printf(s, "Memory info #%d\n", try_count);

    if (NULL != currProcess->mm && NULL != currProcess->mm->pgd){
        seq_printf(s, "PGD base address: 0x%lx\n", (unsigned long) currProcess->mm->pgd);
        printf_code(s, currProcess);
        printf_data(s, currProcess);
        printf_heap(s, currProcess);
        printf_stack(s, currProcess);
        printf_bar(s);
    }
    else
        seq_printf(s, "cannot access task_struct->mm\n");
}

// print PGD, PUD, PMD, PTE, Physical address of currProcess's area
static void printAddressAndValue(struct seq_file* s, struct task_struct* currProcess, unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;

    // get pgd with pgd_offset
    pgd = pgd_offset(currProcess->mm, vaddr);
    if (pgd_none(*pgd)){
        seq_printf(s, "PGD_NONE DETECTED!\n");
        return;
    }
    seq_printf(s, "- PGD address, value: 0x%lx, 0x%lx\n", (unsigned long) pgd, (unsigned long) pgd_val(*pgd));

    // get pud with pud_offset
    pud = pud_offset((p4d_t*) pgd, vaddr);
    if (pud_none(*pud)){
        seq_printf(s, "PUD_NONE DETECTED!\n");
        return;
    }
    seq_printf(s, "- PUD address, value: 0x%lx, 0x%lx\n", (unsigned long) pud, (unsigned long) pud_val(*pud));

    // get pmd with pmd_offset
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)){
        seq_printf(s, "PMD_NONE DETECTED!\n");
        return;
    }
    seq_printf(s, "- PMD address, value: 0x%lx, 0x%lx\n", (unsigned long) pmd, (unsigned long) pmd_val(*pmd));

    // get pte with pte_offset_kernel
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)){
        seq_printf(s, "PTE_NONE DETECTED!\n");
        return;
    }
    seq_printf(s, "- PTE address, value: 0x%lx, 0x%lx\n", (unsigned long) pte, (unsigned long) pte_val(*pte));

    // get actual physical address (bit operations between address and offset)
    page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK;
    paddr = page_addr | page_offset;

    seq_printf(s, "- Physical address: 0x%lx\n", paddr);

    return;
}

/**
 * This function is called at the beginning of a sequence.
 * ie, when:
 * ??? the /proc file is read (first time)
 * ??? after the function stop (end of sequence)
 *
 */
static void *hw2_seq_start(struct seq_file *s, loff_t *pos)
{

    static unsigned long counter = 0;
    /* beginning a new sequence ? */
    if (*pos == 0)
    {
        /* yes => return a non null value to begin the sequence */
        return &counter;
    }
    else
    {
    
        /* no => it's the end of the sequence, return end to stop reading */
        *pos = 0;
        return NULL;
    }
}

/**
 * This function is called after the beginning of a sequence.
 * It's called untill the return is NULL (this ends the sequence).
 *
 */
static void *hw2_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    unsigned long *tmp_v = (unsigned long *)v;
    (*tmp_v)++;
    (*pos)++;
    return NULL;
}

/**
 * This function is called at the end of a sequence
 *
 */
static void hw2_seq_stop(struct seq_file *s, void *v)
{
    /* nothing to do, we use a static value in start() */
}

static struct seq_operations hw2_seq_ops = {
    .start = hw2_seq_start,
    .next = hw2_seq_next,
    .stop = hw2_seq_stop,
    .show = hw2_seq_show
};

static int hw2_proc_open(struct inode *inode, struct file *file) {

    name = file->f_path.dentry->d_name.name;
    return seq_open(file, &hw2_seq_ops);
}

static const struct proc_ops hw2_proc_fops = {
	.proc_open = hw2_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release
};


// for timer
static struct timer_list my_timer;
static void my_timer_func(struct timer_list *unused)
{
    // remove /proc/hw2 directory and recreate
    remove_proc_entry(PROC_NAME, NULL);
    parent = proc_mkdir(PROC_NAME, NULL);

    // increment try count
    try_count++;
    do_job();

    my_timer.expires = jiffies + HZ * period;
    add_timer(&my_timer);
}

static int __init hw2_init(void) {
    // make hw2 directory
    parent = proc_mkdir(PROC_NAME, NULL);

    // 1. traverse user processes and print PGD, PUD, PMD, PTE, Physical address
    do_job();

    // 2. timer => do job per period
    timer_setup(&my_timer, my_timer_func, 0);
    my_timer.expires = jiffies + HZ * period;
    add_timer(&my_timer);

    return 0;
}

static void __exit hw2_exit(void) {
    // remove hw2 directory
    remove_proc_entry(PROC_NAME, NULL);
    del_timer(&my_timer);
}

module_init(hw2_init);
module_exit(hw2_exit);



void do_job(void){
    struct proc_dir_entry *proc_file_entry;
    struct task_struct* task;

    // traverse all processes and create each file
    rcu_read_lock();
    for_each_process(task)
    {
        // filter kernel thread. (cannot access mm, mm->pgd)
        if (NULL != task->mm && NULL != task->mm->pgd){

            // convert pid to string
            char pidStr[10];
            sprintf(pidStr, "%d", task->pid);

            proc_file_entry = proc_create(pidStr, 0, parent, &hw2_proc_fops);
        }
    }
    rcu_read_unlock();
}


// print bars
void printf_bar(struct seq_file* s){
    int i;
    for (i = 0; i < 80; i++) seq_printf(s, "-");
    seq_printf(s, "\n");
}

void printf_code(struct seq_file* s, struct task_struct* currProcess){
    printf_bar(s);
    seq_printf(s, "Code Area Start\n");

    
    // Virtual Addr
    seq_printf(s, "- Virtual address: 0x%lx\n", currProcess->mm->start_code);
    printAddressAndValue(s, currProcess, currProcess->mm->start_code);
    printf_bar(s);
    
    seq_printf(s, "Code Area End\n");
}

void printf_data(struct seq_file* s, struct task_struct* currProcess){
    printf_bar(s);
    seq_printf(s, "Data Area Start\n");
    
    // Virtual Addr
    seq_printf(s, "- Virtual address: 0x%lx\n", currProcess->mm->start_data);
    printAddressAndValue(s, currProcess, currProcess->mm->start_data);
    printf_bar(s);
    
    seq_printf(s, "Data Area End\n");
}

void printf_heap(struct seq_file* s, struct task_struct* currProcess){
    printf_bar(s);
    seq_printf(s, "Heap Area Start\n");
    
    // Virtual Addr
    seq_printf(s, "- Virtual address: 0x%lx\n", currProcess->mm->start_brk);
    printAddressAndValue(s, currProcess, currProcess->mm->start_brk);
    printf_bar(s);
    
    seq_printf(s, "Heap Area End\n");
}

void printf_stack(struct seq_file* s, struct task_struct* currProcess){
    printf_bar(s);
    seq_printf(s, "Stack Area Start\n");

    // Virtual Addr
    seq_printf(s, "- Virtual address: 0x%lx\n", currProcess->mm->start_stack);
    printAddressAndValue(s, currProcess, currProcess->mm->start_stack);
    printf_bar(s);
    
    seq_printf(s, "Stack Area End\n");
}