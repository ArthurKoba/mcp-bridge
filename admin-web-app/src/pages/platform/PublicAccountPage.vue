<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { platformPort } from "@/features/platform/api/port"
import { A11_ACCEPTED_SOURCE_ONLY } from "@/features/platform/api/a11-owner-bff-source"
import { normalizeUiError, type UiError } from "@/features/platform/model/errors"
import { oneUseCommands, type OneUseAttempt } from "@/features/platform/model/one-use-commands"
import Button from "@/shared/ui/Button.vue"

const props=defineProps<{ mode:"invitation" | "reset"; initialToken?:string }>()
const emit=defineEmits<{ back: []; tokenCopied: [] }>()
const {t}=useI18n()
const fields=reactive({token:props.initialToken??"",username:"",password:"",confirm:""})
const busy=ref(false)
const error=ref<UiError|null>(null)
const completed=ref(false)
const uncertain=ref(false)
let controller:AbortController|null=null
let activeAttempt:OneUseAttempt|null=null
let generation=0
const enabled=computed(()=>Boolean(A11_ACCEPTED_SOURCE_ONLY.publicOneUseStatusApproved&&
  platformPort.value?.bff&&
  (props.mode==="invitation"?platformPort.value.auth.register:platformPort.value.auth.redeemPasswordReset)))
const valid=computed(()=>{
  const pwd=fields.password.length>=12 && fields.password.length<=4096 && fields.confirm===fields.password
  if(props.mode==="reset")return fields.token.trim().length>=10&&fields.token.trim().length<=512&&pwd
  return fields.token.trim().length>=10 && fields.token.trim().length<=512 &&
    fields.username.trim().length>=3 && fields.username.trim().length<=128 && pwd
})
function clearSensitive() {
  ++generation
  if(activeAttempt)oneUseCommands.uncertain(activeAttempt)
  activeAttempt=null
  controller?.abort()
  controller = null
  fields.token=""
  fields.password=""
  fields.confirm=""
  fields.username=""
  busy.value=false
  error.value=null
  uncertain.value=false
}
watch(() => props.mode, () => { clearSensitive(); completed.value=false })
onMounted(() => {
  if(props.initialToken)emit("tokenCopied")
  if(!enabled.value){
    // A link opened before approved first-user/one-use BFF cannot be
    // consumed or kept in a dormant form and must never fake completion.
    fields.token=""
    fields.password=""
    fields.confirm=""
  }
})
onBeforeUnmount(clearSensitive)
async function submit(){
  if(!enabled.value || !valid.value || busy.value || uncertain.value || completed.value)return
  const port=platformPort.value
  if(!port)return
  const mode=props.mode
  const token=fields.token.trim()
  // Capture the accepted A4 one-use command before any asynchronous work.
  // Never claim a successful signup/reset after a missing adapter operation.
  let invoke:(signal:AbortSignal,idempotencyKey:string)=>Promise<void>
  if(mode==="invitation"){
    const register=port.auth.register
    if(!register)return
    const input={invitationToken:token,username:fields.username.trim(),password:fields.password}
    invoke=(signal,key)=>register(input,signal,key)
  }else{
    const redeem=port.auth.redeemPasswordReset
    if(!redeem)return
    const input={resetToken:token,password:fields.password}
    invoke=(signal,key)=>redeem(input,signal,key)
  }
  const attemptGeneration=++generation
  const current=new AbortController()
  controller=current
  busy.value=true
  error.value=null
  try{
    const attempt=await oneUseCommands.begin(mode,token)
    if(!attempt){
      uncertain.value=true
      return
    }
    activeAttempt=attempt
    if(current.signal.aborted||attemptGeneration!==generation||props.mode!==mode||platformPort.value!==port){
      oneUseCommands.uncertain(attempt)
      activeAttempt=null
      return
    }
    await invoke(current.signal,attempt.idempotencyKey)
    // Source A11 does not expose a signed owner-global one-use outcome.
    // Even a successful local HTTP response cannot prove that redemption
    // committed and permission/grant revocation reached all owners.
    oneUseCommands.uncertain(attempt)
    activeAttempt=null
    if(current.signal.aborted||props.mode!==mode||platformPort.value!==port||controller!==current)return
    uncertain.value=true
  }catch(cause){
    const normalized=normalizeUiError(cause,"mutation")
    if(activeAttempt){
      // Until Backend publishes an independently verified signed one-use
      // rejection, even a 400/422 AFTER invocation might follow a commit.
      oneUseCommands.uncertain(activeAttempt)
      activeAttempt=null
    }
    if(!current.signal.aborted&&controller===current&&props.mode===mode&&platformPort.value===port){
      error.value=normalized
      uncertain.value=true
    }
  }finally{
    if(controller===current){
      busy.value=false
      // Password/token fields never survive a sent one-use command.
      fields.token=""
      fields.password=""
      fields.confirm=""
      controller=null
    }
  }
}
</script>
<template>
  <section class="w-full max-w-md space-y-4 rounded-xl border border-border bg-card p-6 shadow-sm">
    <h1 class="text-lg font-semibold">{{mode==='invitation'?t('platform.registerTitle'):t('platform.resetTitle')}}</h1>
    <p class="text-xs text-muted-foreground">{{mode==='invitation'?t('platform.registerHint'):t('platform.resetHint')}}</p>
    <div v-if="!enabled" role="status" class="rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">{{t('platform.oneUseSourceNotApproved')}}</div>
    <p v-if="completed" role="status" class="text-sm">{{t('platform.publicComplete')}}</p>
    <p v-if="uncertain" role="alert" class="rounded-md border border-destructive/30 p-3 text-sm text-destructive">{{t('platform.publicMutationUncertain')}}</p>
    <form v-else-if="!completed" class="space-y-3" @submit.prevent="submit">
      <label class="block text-xs">{{mode==='invitation'?t('platform.invitationToken'):t('platform.resetToken')}}<input v-model="fields.token" class="field mt-1" type="password" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" maxlength="512" :disabled="!enabled || busy" required /></label>
      <label v-if="mode==='invitation'" class="block text-xs">{{t('app.username')}}<input v-model="fields.username" class="field mt-1" autocomplete="username" minlength="3" maxlength="128" :disabled="!enabled || busy" required /></label>
      <label class="block text-xs">{{t('platform.newPassword')}}<input v-model="fields.password" class="field mt-1" type="password" autocomplete="new-password" minlength="12" maxlength="4096" :disabled="!enabled || busy" required /></label>
      <label class="block text-xs">{{t('platform.confirmPassword')}}<input v-model="fields.confirm" class="field mt-1" type="password" autocomplete="new-password" minlength="12" maxlength="4096" :disabled="!enabled || busy" required /></label>
      <p v-if="error" class="text-xs text-destructive" role="alert">{{t(`platform.errors.${error.message}`)}}</p>
      <Button class="w-full" type="submit" :disabled="!enabled || !valid || busy || uncertain">{{mode==='invitation'?t('platform.register'):t('platform.submitResetPassword')}}</Button>
    </form>
    <Button variant="outline" class="w-full" @click="emit('back')">{{t('platform.backToSignIn')}}</Button>
  </section>
</template>
